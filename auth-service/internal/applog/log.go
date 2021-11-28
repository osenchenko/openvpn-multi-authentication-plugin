package applog

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

//NewProductionAppLogger creates app logger. Logger stores messages in
//application log text file
func NewProductionAppLogger(p string, level zapcore.Level) *zap.SugaredLogger {
	ecfg := zap.NewProductionEncoderConfig()
	ecfg.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg := zap.Config{
		Level:             zap.NewAtomicLevelAt(level),
		Encoding:          "json",
		EncoderConfig:     ecfg,
		DisableStacktrace: true,
		OutputPaths:       []string{p},
	}
	logger, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	slogger := logger.Sugar()
	return slogger
}

//NewQAAppLogger logs messages to stdout, stderr
func NewQAAppLogger() *zap.SugaredLogger {
	ecfg := zap.NewProductionEncoderConfig()
	ecfg.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg := zap.Config{
		Level:         zap.NewAtomicLevelAt(zap.DebugLevel),
		Encoding:      "console",
		EncoderConfig: ecfg,
		OutputPaths:   []string{"stdout"},
	}
	logger, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	slogger := logger.Sugar()
	return slogger
}

func NewLogger(p string, logLvlStr string) *zap.SugaredLogger {
	var lvl zapcore.Level

	switch logLvlStr {
	case "error":
		lvl = zap.ErrorLevel
	case "info":
		lvl = zap.InfoLevel
	case "warn":
		lvl = zap.WarnLevel
	case "debug":
		lvl = zap.DebugLevel
	default:
		lvl = zap.ErrorLevel
	}

	return NewProductionAppLogger(p, lvl)
}
