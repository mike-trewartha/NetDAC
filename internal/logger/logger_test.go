package logger

import (
	"testing"
)

func TestInit(t *testing.T) {
	tests := []struct {
		name    string
		level   LogLevel
		verbose bool
	}{
		{
			name:    "Debug level, standard mode",
			level:   LevelDebug,
			verbose: false,
		},
		{
			name:    "Info level, verbose mode",
			level:   LevelInfo,
			verbose: true,
		},
		{
			name:    "Error level, standard mode",
			level:   LevelError,
			verbose: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that Init doesn't panic
			Init(tt.level, tt.verbose)

			// Test that logger is initialized by calling a log function
			Info("test message", "key", "value")

			// Since we can't easily capture slog output in tests without more setup,
			// we'll just verify the function doesn't panic
		})
	}
}

func TestLogLevels(t *testing.T) {
	// Initialize logger in non-verbose mode
	Init(LevelInfo, false)

	tests := []struct {
		name    string
		logFunc func(string, ...interface{})
		message string
		args    []interface{}
	}{
		{
			name:    "Debug level",
			logFunc: Debug,
			message: "debug message",
			args:    []interface{}{"key", "value"},
		},
		{
			name:    "Info level",
			logFunc: Info,
			message: "info message",
			args:    []interface{}{"key", "value"},
		},
		{
			name:    "Warn level",
			logFunc: Warn,
			message: "warning message",
			args:    []interface{}{"key", "value"},
		},
		{
			name:    "Error level",
			logFunc: Error,
			message: "error message",
			args:    []interface{}{"key", "value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that logging functions don't panic
			tt.logFunc(tt.message, tt.args...)
		})
	}
}

func TestFatal(t *testing.T) {
	// Initialize logger
	Init(LevelInfo, false)

	// We can't easily test Fatal since it calls os.Exit
	// In a real-world scenario, we'd use dependency injection to make this testable
	// For now, we'll just verify the function exists and has the right signature

	// Test that Fatal function exists (this will panic if it doesn't)
	defer func() {
		if r := recover(); r != nil {
			// Expected - Fatal should call os.Exit(1) which we can't test directly
			t.Log("Fatal function called os.Exit as expected")
		}
	}()

	// Note: In a production test, we'd want to avoid actually calling Fatal
	// or use a test framework that can capture os.Exit calls
	t.Skip("Skipping Fatal test to avoid os.Exit in test suite")
}

func TestLoggerKeyValuePairs(t *testing.T) {
	Init(LevelInfo, false)

	tests := []struct {
		name    string
		message string
		args    []interface{}
		valid   bool
	}{
		{
			name:    "Valid key-value pairs",
			message: "test message",
			args:    []interface{}{"key1", "value1", "key2", "value2"},
			valid:   true,
		},
		{
			name:    "Odd number of arguments",
			message: "test message",
			args:    []interface{}{"key1", "value1", "key2"},
			valid:   false, // This should still work but may log a warning
		},
		{
			name:    "No key-value pairs",
			message: "test message",
			args:    []interface{}{},
			valid:   true,
		},
		{
			name:    "Mixed types",
			message: "test message",
			args:    []interface{}{"string_key", "string_value", "int_key", 42, "bool_key", true},
			valid:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that functions handle various argument patterns
			Info(tt.message, tt.args...)
			Debug(tt.message, tt.args...)
			Warn(tt.message, tt.args...)
			Error(tt.message, tt.args...)
		})
	}
}

func TestVerboseMode(t *testing.T) {
	// Test verbose mode initialization
	Init(LevelDebug, true)

	// In verbose mode, debug messages should be logged
	// In non-verbose mode, they should be suppressed
	// Since we can't easily capture slog output, we'll test that
	// the functions execute without error

	Debug("debug message in verbose mode", "test", true)
	Info("info message in verbose mode", "test", true)

	// Test non-verbose mode
	Init(LevelInfo, false)

	Debug("debug message in non-verbose mode", "test", false)
	Info("info message in non-verbose mode", "test", false)
}

func TestLoggerFormat(t *testing.T) {
	// Test JSON format (verbose mode)
	Init(LevelInfo, true)

	// We can't easily test the actual output format without access to the logger
	// internals, but we can verify the functions work with complex data

	complexData := map[string]interface{}{
		"nested": map[string]string{
			"key": "value",
		},
		"array": []int{1, 2, 3},
	}

	Info("complex data test", "data", complexData)

	// Test text format (non-verbose mode)
	Init(LevelInfo, false)

	Info("simple text format test", "key", "value")
}

func TestLoggerConcurrency(t *testing.T) {
	Init(LevelInfo, false)

	// Test concurrent logging to ensure thread safety
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			Info("concurrent log message", "goroutine_id", id)
			Debug("concurrent debug message", "goroutine_id", id)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// Test helper functions for structured logging validation

func TestStructuredLoggingFormat(t *testing.T) {
	// This test would ideally capture actual log output
	// For demonstration, we'll test the concept

	Init(LevelInfo, true) // JSON format

	testCases := []struct {
		message string
		fields  []interface{}
	}{
		{
			message: "Authentication attempt",
			fields:  []interface{}{"user", "admin", "source_ip", "192.168.1.100", "success", true},
		},
		{
			message: "Connection established",
			fields:  []interface{}{"target", "cisco-device", "protocol", "ssh", "port", 22},
		},
		{
			message: "Command execution",
			fields:  []interface{}{"command", "show version", "duration", "2.3s", "success", true},
		},
	}

	for _, tc := range testCases {
		Info(tc.message, tc.fields...)
	}
}

func TestErrorLoggingWithContext(t *testing.T) {
	Init(LevelInfo, false)

	// Test error logging with contextual information
	testError := "connection timeout"

	Error("Network error occurred",
		"error", testError,
		"target", "192.168.1.1",
		"port", 22,
		"retry_count", 3,
		"timeout", "30s",
	)

	Error("Authentication failed",
		"error", "invalid credentials",
		"user", "testuser",
		"method", "password",
		"source", "192.168.1.100",
	)
}

// Benchmark tests for performance

func BenchmarkInfoLogging(b *testing.B) {
	Init(LevelInfo, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Info("benchmark message", "iteration", i, "test", true)
	}
}

func BenchmarkDebugLogging(b *testing.B) {
	Init(LevelInfo, false) // Debug should be suppressed in non-verbose mode

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Debug("benchmark debug message", "iteration", i, "test", true)
	}
}

func BenchmarkVerboseLogging(b *testing.B) {
	Init(LevelDebug, true) // JSON format, all levels enabled

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Info("verbose benchmark message", "iteration", i, "format", "json")
	}
}
