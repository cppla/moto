package main

import (
	"flag"
	"fmt"
	"moto/config"
	"moto/controller"
	"moto/utils"
	"os"
	"sync"
)

func main() {
	conf := flag.String("config", "", "Path to config file")
	flag.Parse()

	// Load config if a path is provided; overrides default and env
	if *conf != "" {
		if err := config.Reload(*conf); err != nil {
			fmt.Printf("failed to load config: %v\n", err)
			os.Exit(1)
		}
	}

	defer utils.Logger.Sync()

	utils.Logger.Info("MOTO 启动...")
	// single-sided build: no accelerator init required
	wg := &sync.WaitGroup{}
	for _, v := range config.GlobalCfg.Rules {
		wg.Add(1)
		go controller.Listen(v, wg)
	}
	wg.Wait()
	utils.Logger.Info("MOTO 关闭...")
}
