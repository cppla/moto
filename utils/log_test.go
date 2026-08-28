package utils

import (
	"encoding/json"
	"moto/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

func TestTimeEncoderUsesLocalTimeWithSecondPrecision(t *testing.T) {
	location := time.FixedZone("UTC+8", 8*60*60)

	encoder := zapcore.NewJSONEncoder(zapcore.EncoderConfig{
		TimeKey:    "ts",
		MessageKey: "msg",
		EncodeTime: func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
			appendTimeInLocation(t, location, enc)
		},
	})
	entry := zapcore.Entry{
		Time:    time.Date(2026, time.August, 27, 9, 3, 6, 987654321, time.UTC),
		Message: "time-format-test",
	}
	buffer, err := encoder.EncodeEntry(entry, nil)
	if err != nil {
		t.Fatalf("EncodeEntry() error = %v", err)
	}
	defer buffer.Free()

	var decoded struct {
		Timestamp string `json:"ts"`
	}
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("decode log entry: %v", err)
	}
	if decoded.Timestamp != "2026-08-27 17:03:06" {
		t.Fatalf("timestamp = %q, want %q", decoded.Timestamp, "2026-08-27 17:03:06")
	}
}
