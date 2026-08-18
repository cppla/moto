package utils

import (
	"moto/config"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestLoggerHasSafeDefault(t *testing.T) {
	if Logger == nil {
		t.Fatal("Logger is nil before Configure")
	}
	Logger.Debug("safe before configuration")
}

func TestConfigureRejectsInvalidConfigWithoutReplacingLogger(t *testing.T) {
	previous := Logger
	if err := Configure(config.LogConfig{Level: "verbose"}); err == nil {
		t.Fatal("Configure() succeeded, want error")
	}
	if Logger != previous {
		t.Fatal("failed Configure() replaced Logger")
	}
}

func TestConfigureWritesFilteredRollingFile(t *testing.T) {
	previous := Logger
	t.Cleanup(func() { Logger = previous })

	path := filepath.Join(t.TempDir(), "moto.log")
	if err := Configure(config.LogConfig{Level: "info", Path: path}); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	Logger.Debug("hidden-message")
	Logger.Info("visible-message", zap.String("source", "test"))
	_ = Logger.Sync()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "visible-message") || !strings.Contains(text, `"source":"test"`) {
		t.Fatalf("log file missing info entry: %s", text)
	}
	if strings.Contains(text, "hidden-message") {
		t.Fatalf("debug entry bypassed info level: %s", text)
	}
}

func TestConfigureAllowsStdoutOnly(t *testing.T) {
	previous := Logger
	t.Cleanup(func() { Logger = previous })
	if err := Configure(config.LogConfig{Level: "warn"}); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	Logger.Warn("stdout-only")
}
