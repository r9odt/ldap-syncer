// Package logging contains project logging functions
package logging

// Logger implements logger abstraction.
type Logger interface {
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
	Warning(args ...interface{})
	Warningf(format string, args ...interface{})

	// Structured logging methods, use to add context fields
	String(key, value string) Logger
	Int(key string, value int) Logger
	Int64(key string, value int64) Logger
	Interface(key string, value interface{}) Logger
	Bytes(key string, value []byte) Logger
	Fields(fields map[string]interface{}) Logger

	// Get child logger with the minimum accepted level
	Level(string) (Logger, error)
	// Returns new copy of log, when need to avoid context duplication
	Clone() Logger
}
