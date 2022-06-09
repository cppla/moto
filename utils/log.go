package utils

import (
	"github.com/natefinch/lumberjack"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"moto/config"
	"time"
)

var (
	Logger *zap.Logger
)

func init()  {
	highPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool{
		return lvl >= levelMap[config.GlobalCfg.Log.Level]
	})

	//lowPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
	//	return lvl >= zapcore.DebugLevel
	//})

	hook := lumberjack.Logger{
		Filename:   config.GlobalCfg.Log.Path,
		MaxSize:    1024,
		MaxBackups: 5,
		MaxAge:     30,
		Compress:   true,
	}

	//consoles := zapcore.AddSync(os.Stdout)
	files := zapcore.AddSync(&hook)


	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		//CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		//EncodeLevel:	zapcore.CapitalColorLevelEncoder,
		EncodeTime:     TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	//consoleEncoder := zapcore.NewJSONEncoder(encoderConfig)
	fileEncoder := zapcore.NewJSONEncoder(encoderConfig)

	core := zapcore.NewTee(
		//zapcore.NewCore(consoleEncoder, consoles, lowPriority),
		zapcore.NewCore(fileEncoder, files, highPriority),
	)

	Logger = zap.New(
		core,
		zap.AddCaller(),
		zap.Development())

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

func TimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("2006-01-02 15:04:05.000"))
}