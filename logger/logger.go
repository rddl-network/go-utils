package logger

import (
	"fmt"
	"os"
	"slices"

	stdLog "log"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

const (
	DEBUG = "debug"
	INFO  = "info"
	WARN  = "warn"
	ERROR = "error"
	DEPTH = 6 // DEPTH set to 6 so logger.Error() or similar returns the caller of said function
)

type AppLogger struct {
	logger log.Logger
}

func GetLogger(logLevel string) AppLogger {
	var logger log.Logger
	logger = log.NewLogfmtLogger(os.Stderr)
	logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.Caller(DEPTH))

	// logLevel should be set to "debug", "info", "warn", or "error"
	if !slices.Contains([]string{DEBUG, INFO, WARN, ERROR}, logLevel) {
		stdLog.Panicln("logLevel should be set to debug, info, warn or error")
	}

	// Set log level
	switch logLevel {
	case DEBUG:
		logger = level.NewFilter(logger, level.AllowDebug())
	case INFO:
		logger = level.NewFilter(logger, level.AllowInfo())
	case WARN:
		logger = level.NewFilter(logger, level.AllowWarn())
	default:
		logger = level.NewFilter(logger, level.AllowError())
	}

	return AppLogger{logger}
}

func (al AppLogger) Error(kevals ...interface{}) {
	err := level.Error(al.logger).Log(kevals...)
	if err != nil {
		fmt.Println(err)
	}
}

func (al AppLogger) Warn(kevals ...interface{}) {
	err := level.Warn(al.logger).Log(kevals...)
	if err != nil {
		fmt.Println(err)
	}
}

func (al AppLogger) Info(kevals ...interface{}) {
	err := level.Info(al.logger).Log(kevals...)
	if err != nil {
		fmt.Println(err)
	}
}

func (al AppLogger) Debug(kevals ...interface{}) {
	err := level.Debug(al.logger).Log(kevals...)
	if err != nil {
		fmt.Println(err)
	}
}
