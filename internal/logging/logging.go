package logging

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/rs/zerolog"
)

// ZLogger is implementation of zerolog logger
type ZLogger struct {
	zerolog.Logger
}

const (
	// ModuleFieldName is tag for module name in log output
	ModuleFieldName = "module"
	// FileFieldName is tag for file name in log output
	FileFieldName = "file"
	// PackageFieldName is tag for package name in log output
	PackageFieldName = "package"
	// FuncFieldName is tag for func name in log output
	FuncFieldName = "func"
	// DefaultTimeFormat is time format
	DefaultTimeFormat = "2006-01-02 15:04:05.000"
)

// ConfigureLog creates new logger based on github.com/rs/zerolog package
func ConfigureLog(logFile, logLevel, module string, pretty bool) (*ZLogger, error) {
	return newLog(logFile, logLevel, module, pretty, false)
}

// GetLogger need only for backward compatibility in tests
func GetLogger(module string) (Logger, error) {
	return newLog("stdout", "info", module, true, true)
}

func newLog(logFile, logLevel, module string, pretty, colorOff bool) (*ZLogger, error) {
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		level = zerolog.DebugLevel
	}

	logWriter, err := getLogWriter(logFile)
	if err != nil {
		return nil, err
	}
	zerolog.TimeFieldFormat = DefaultTimeFormat

	if pretty {
		logWriter = zerolog.ConsoleWriter{
			Out:        logWriter,
			NoColor:    colorOff,
			TimeFormat: DefaultTimeFormat,
			PartsOrder: []string{zerolog.TimestampFieldName, ModuleFieldName,
				zerolog.LevelFieldName, zerolog.MessageFieldName},
		}
	}

	l := zerolog.New(logWriter).Level(level).With().Str(ModuleFieldName,
		module).Logger().Hook(CallerHook{})

	return &ZLogger{l}, nil
}

func getLogWriter(logFileName string) (io.Writer, error) {
	if logFileName == "stdout" || logFileName == "" {
		return os.Stdout, nil
	}

	logDir := filepath.Dir(logFileName)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("can't create log directories %s: %s", logDir,
			err.Error())
	}
	logFile, err := os.OpenFile(logFileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND,
		0644)
	if err != nil {
		return nil, fmt.Errorf("can't open log file %s: %s", logFileName,
			err.Error())
	}
	return logFile, nil
}

func getCaller() (string, string, string) {
	fun := "???"
	pkg := "???"
	pc, file, line, ok := runtime.Caller(5)
	if ok {
		file = filepath.Base(file)

		if f := runtime.FuncForPC(pc); f != nil {
			name := f.Name()
			i := strings.LastIndex(name, "/")
			j := strings.Index(name[i+1:], ".")

			if j >= 1 {
				pkg, fun = name[:i+j+1], name[i+j+2:]
			}
		}
	} else {
		file = "???"
		line = 0
	}

	return path.Base(pkg), fmt.Sprintf("%s:%d", file, line), fun
}

// CallerHook is caller hook structure
type CallerHook struct{}

// Run is caller hook for add some fields for every logging call
func (h CallerHook) Run(event *zerolog.Event, _ zerolog.Level, _ string) {
	pack, file, fun := getCaller()
	event.Str(PackageFieldName, pack)
	event.Str(FileFieldName, file)
	event.Str(FuncFieldName, fun)
}

// Debug prints message for debug level
func (l ZLogger) Debug(args ...interface{}) {
	event := l.Logger.Debug()
	if event == nil {
		return
	}
	event.Timestamp().Msg(fmt.Sprint(args...))
}

// Debugf prints message for debug level
func (l ZLogger) Debugf(format string, args ...interface{}) {
	event := l.Logger.Debug()
	if event == nil {
		return
	}
	event.Timestamp().Msgf(format, args...)
}

// Info prints message for info level
func (l ZLogger) Info(args ...interface{}) {
	event := l.Logger.Info()
	if event == nil {
		return
	}
	event.Timestamp().Msg(fmt.Sprint(args...))
}

// Infof prints message for info level
func (l ZLogger) Infof(format string, args ...interface{}) {
	event := l.Logger.Info()
	if event == nil {
		return
	}
	event.Timestamp().Msgf(format, args...)
}

// Error prints message for error level
func (l ZLogger) Error(args ...interface{}) {
	event := l.Logger.Error()
	if event == nil {
		return
	}
	event.Timestamp().Msgf("%s", fmt.Sprint(args...))
}

// Errorf prints message for error level
func (l ZLogger) Errorf(format string, args ...interface{}) {
	event := l.Logger.Error()
	if event == nil {
		return
	}
	event.Timestamp().Msgf(format, args...)
}

// Fatal prints message for fatal level
func (l ZLogger) Fatal(args ...interface{}) {
	event := l.Logger.Fatal()
	if event == nil {
		return
	}
	event.Timestamp().Msg(fmt.Sprint(args...))
}

// Fatalf prints message for fatal level
func (l ZLogger) Fatalf(format string, args ...interface{}) {
	event := l.Logger.Fatal()
	if event == nil {
		return
	}
	event.Timestamp().Msgf(format, args...)
}

// Warning prints message for warning level
func (l ZLogger) Warning(args ...interface{}) {
	event := l.Warn()
	if event == nil {
		return
	}
	event.Timestamp().Msg(fmt.Sprint(args...))
}

// Warningf prints message for warning level
func (l ZLogger) Warningf(format string, args ...interface{}) {
	event := l.Warn()
	if event == nil {
		return
	}
	event.Timestamp().Msgf(format, args...)
}

// String adding string value to log output
func (l *ZLogger) String(key, value string) Logger {
	l.Logger = l.Logger.With().Str(key, value).Logger()
	return l
}

// Int adding int value to log output
func (l *ZLogger) Int(key string, value int) Logger {
	l.Logger = l.Logger.With().Int(key, value).Logger()
	return l
}

// Int64 adding int64 value to log output
func (l *ZLogger) Int64(key string, value int64) Logger {
	l.Logger = l.Logger.With().Int64(key, value).Logger()
	return l
}

// Interface adding interface value to log output
func (l *ZLogger) Interface(key string, value interface{}) Logger {
	l.Logger = l.Logger.With().Interface(key, value).Logger()
	return l
}

// Bytes adding bytes value to log output
func (l *ZLogger) Bytes(key string, value []byte) Logger {
	l.Logger = l.Logger.With().Bytes(key, value).Logger()
	return l
}

// Fields adding fields map to log output
func (l *ZLogger) Fields(fields map[string]interface{}) Logger {
	l.Logger = l.Logger.With().Fields(fields).Logger()
	return l
}

// Level set logging level for logger
func (l *ZLogger) Level(s string) (Logger, error) {
	level, err := zerolog.ParseLevel(s)
	if err != nil {
		return l, err
	}
	l.Logger = l.Logger.Level(level)
	return l, nil
}

// Clone clones Zlogger structure
func (l ZLogger) Clone() Logger {
	return &ZLogger{
		Logger: l.Logger.With().Logger(),
	}
}
