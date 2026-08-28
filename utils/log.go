package utils

import (
	"moto/config"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger is always safe to use, even before logging is configured.
var Logger = zap.NewNop()

// Configure replaces Logger with a stdout logger and, when Path is non-empty,
// a second rolling JSON log destination.
func Configure(cfg config.LogConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	level := levelMap[cfg.Level]
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	encoder := zapcore.NewJSONEncoder(encoderConfig)
	enabler := zap.LevelEnablerFunc(func(candidate zapcore.Level) bool {
		return candidate >= level
	})

	cores := []zapcore.Core{
		zapcore.NewCore(encoder, zapcore.Lock(os.Stdout), enabler),
	}
	if cfg.Path != "" {
		hook := &lumberjack.Logger{
			Filename:   cfg.Path,
			MaxSize:    100,
			MaxBackups: 5,
			MaxAge:     30,
			Compress:   true,
		}
		cores = append(cores, zapcore.NewCore(encoder, zapcore.AddSync(hook), enabler))
	}

	Logger = zap.New(zapcore.NewTee(cores...), zap.AddCaller())
	return nil
}

var levelMap = map[string]zapcore.Level{
	"debug":  zapcore.DebugLevel,
	"info":   zapcore.InfoLevel,
	"warn":   zapcore.WarnLevel,
	"error":  zapcore.ErrorLevel,
	"dpanic": zapcore.DPanicLevel,
	"panic":  zapcore.PanicLevel,
	"fatal":  zapcore.FatalLevel,
}

const logTimeLayout = "2006-01-02 15:04:05"

func TimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	appendTimeInLocation(t, time.Local, enc)
}

func appendTimeInLocation(t time.Time, location *time.Location, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.In(location).Format(logTimeLayout))
}

// optional helpers for structured fields (used in some modules)
func ZapString(k, v string) zap.Field { return zap.String(k, v) }
func ZapErr(err error) zap.Field      { return zap.Error(err) }
