package logger

import (
	"os"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	globalLogger atomic.Pointer[zap.Logger]
	globalSugar  atomic.Pointer[zap.SugaredLogger]
	once         sync.Once
)

type Options struct {
	Level  string // debug, info, warn, error
	Format string // console, json
	File   string // empty = stdout
}

func Init(opts Options) {
	once.Do(func() {
		l := build(opts)
		s := l.Sugar()
		globalLogger.Store(l)
		globalSugar.Store(s)
	})
}

func initDefault() {
	Init(Options{Level: "info", Format: "console"})
}

// L returns the global zap.Logger, lazily initializing with defaults if needed.
func L() *zap.Logger {
	if l := globalLogger.Load(); l != nil {
		return l
	}
	initDefault()
	return globalLogger.Load()
}

// S returns the global sugared logger for printf-style usage.
func S() *zap.SugaredLogger {
	if s := globalSugar.Load(); s != nil {
		return s
	}
	initDefault()
	return globalSugar.Load()
}

// Sync flushes buffered log entries. Call before exit.
func Sync() {
	if l := globalLogger.Load(); l != nil {
		_ = l.Sync()
	}
}

// Named returns a named child logger.
func Named(name string) *zap.Logger {
	return L().Named(name)
}

func build(opts Options) *zap.Logger {
	level := parseLevel(opts.Level)

	encoderCfg := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	var encoder zapcore.Encoder
	if opts.Format == "json" {
		encoderCfg.EncodeLevel = zapcore.LowercaseLevelEncoder
		encoder = zapcore.NewJSONEncoder(encoderCfg)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderCfg)
	}

	var writers []zapcore.WriteSyncer
	writers = append(writers, zapcore.AddSync(os.Stdout))

	if opts.File != "" {
		f, err := os.OpenFile(opts.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			writers = append(writers, zapcore.AddSync(f))
		}
	}

	core := zapcore.NewCore(encoder, zapcore.NewMultiWriteSyncer(writers...), level)
	return zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
}

func parseLevel(s string) zapcore.Level {
	switch s {
	case "debug":
		return zapcore.DebugLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}
