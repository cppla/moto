package main

import (
	"context"
	"flag"
	"fmt"
	"moto/config"
	"moto/controller"
	"moto/utils"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "moto: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	conf := flag.String("config", "", "配置文件路径")
	checkConfig := flag.Bool("check-config", false, "只校验配置，不启动监听")
	showVersion := flag.Bool("version", false, "显示版本信息")
	flag.Parse()
	if *showVersion {
		fmt.Printf("moto %s (commit %s, built %s)\n", version, commit, buildDate)
		return nil
	}

	path := *conf
	if path == "" {
		path = os.Getenv("MOTO_CONFIG")
	}
	if path == "" {
		path = config.DefaultPath
	}

	cfg, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("加载配置 %q: %w", path, err)
	}
	if *checkConfig {
		fmt.Printf("配置有效: %s（%d 条规则）\n", path, len(cfg.Rules))
		return nil
	}

	if err := utils.Configure(cfg.Log); err != nil {
		return fmt.Errorf("初始化日志: %w", err)
	}
	defer func() { _ = utils.Logger.Sync() }()

	metricsListen := ""
	if cfg.Metrics.Enabled {
		metricsListen = cfg.Metrics.Listen
	}
	server, err := controller.NewServerWithMetrics(cfg.Rules, metricsListen)
	if err != nil {
		return err
	}
	defer server.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	reloadSignals, stopReloadSignals := notifyReloadSignals()
	defer stopReloadSignals()

	utils.Logger.Info("MOTO 启动",
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("buildDate", buildDate),
		zap.String("config", path),
		zap.Int("rules", len(cfg.Rules)),
		zap.Bool("metricsEnabled", cfg.Metrics.Enabled),
		zap.String("metricsListen", metricsListen))
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()
	current := cfg
	for {
		select {
		case err := <-serveDone:
			if err != nil {
				return err
			}
			utils.Logger.Info("MOTO 关闭")
			return nil
		case <-reloadSignals:
			next, loadErr := config.Load(path)
			if loadErr != nil {
				utils.Logger.Error("配置热重载失败，继续使用当前配置",
					zap.String("config", path), zap.Error(loadErr))
				continue
			}
			if next.Log != current.Log {
				utils.Logger.Error("配置热重载被拒绝：日志配置变更需要重启",
					zap.String("config", path))
				continue
			}
			if next.Metrics != current.Metrics {
				utils.Logger.Error("配置热重载被拒绝：观测监听配置变更需要重启",
					zap.String("config", path))
				continue
			}
			result, reloadErr := server.ReloadRules(ctx, next.Rules)
			if reloadErr != nil {
				utils.Logger.Error("配置热重载失败，继续使用当前配置",
					zap.String("config", path), zap.Error(reloadErr))
				continue
			}
			current = next
			utils.Logger.Info("配置热重载完成",
				zap.String("config", path),
				zap.Uint64("fromGeneration", result.FromGeneration),
				zap.Uint64("toGeneration", result.ToGeneration),
				zap.Bool("noop", result.Noop),
				zap.Int("rules", len(next.Rules)),
				zap.Strings("listenersAdded", result.Added),
				zap.Strings("listenersRemoved", result.Removed))
		}
	}
}
