package logger

import (
	"log/slog"
	"os"
)

var (
	// Global logger instance
	Logger *slog.Logger
)

// LogLevel represents the logging level
type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
)

// Init initializes the structured logger with the specified level and format
func Init(level LogLevel, verbose bool) {
	var logLevel slog.Level

	// Set log level based on input
	switch level {
	case LevelDebug:
		logLevel = slog.LevelDebug
	case LevelInfo:
		logLevel = slog.LevelInfo
	case LevelWarn:
		logLevel = slog.LevelWarn
	case LevelError:
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	// Create handler options
	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	var handler slog.Handler
	if verbose {
		// Use JSON handler for verbose/structured output
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		// Use text handler for human-readable output
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	// Create and set the global logger
	Logger = slog.New(handler)
	slog.SetDefault(Logger)
}

// Info logs an info level message
func Info(msg string, args ...any) {
	Logger.Info(msg, args...)
}

// Debug logs a debug level message
func Debug(msg string, args ...any) {
	Logger.Debug(msg, args...)
}

// Warn logs a warning level message
func Warn(msg string, args ...any) {
	Logger.Warn(msg, args...)
}

// Error logs an error level message
func Error(msg string, args ...any) {
	Logger.Error(msg, args...)
}

// Fatal logs an error and exits the program
func Fatal(msg string, args ...any) {
	Logger.Error(msg, args...)
	os.Exit(1)
}

// WithContext creates a new logger with additional context
func WithContext(args ...any) *slog.Logger {
	return Logger.With(args...)
}
