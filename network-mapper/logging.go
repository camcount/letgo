package networkmapper

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// LogLevel represents different logging levels
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelFatal
)

// String returns the string representation of LogLevel
func (l LogLevel) String() string {
	switch l {
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	case LogLevelWarn:
		return "WARN"
	case LogLevelError:
		return "ERROR"
	case LogLevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// LogEntry represents a single log entry
type LogEntry struct {
	Timestamp time.Time
	Level     LogLevel
	Component string
	Message   string
	Fields    map[string]any
	Error     error
	File      string
	Line      int
}

// NetworkMapperLogger provides comprehensive logging for the network mapper
type NetworkMapperLogger struct {
	level      LogLevel
	writers    []io.Writer
	mutex      sync.RWMutex
	component  string
	fields     map[string]any
	logFile    *os.File
	enableFile bool
}

// NewNetworkMapperLogger creates a new logger instance
func NewNetworkMapperLogger(component string, level LogLevel) *NetworkMapperLogger {
	logger := &NetworkMapperLogger{
		level:     level,
		component: component,
		fields:    make(map[string]any),
		writers:   []io.Writer{os.Stdout}, // Default to stdout
	}

	return logger
}

// NewNetworkMapperLoggerWithFile creates a logger that writes to both console and file
func NewNetworkMapperLoggerWithFile(component string, level LogLevel, logDir string) (*NetworkMapperLogger, error) {
	logger := NewNetworkMapperLogger(component, level)

	if err := logger.EnableFileLogging(logDir); err != nil {
		return nil, fmt.Errorf("failed to enable file logging: %w", err)
	}

	return logger, nil
}

// EnableFileLogging enables logging to a file in the specified directory
func (l *NetworkMapperLogger) EnableFileLogging(logDir string) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	// Create log directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Create log file with timestamp
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("network-mapper_%s_%s.log", l.component, timestamp)
	logPath := filepath.Join(logDir, filename)

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	// Close existing log file if any
	if l.logFile != nil {
		l.logFile.Close()
	}

	l.logFile = file
	l.enableFile = true

	// Add file writer to the list
	l.writers = append(l.writers, file)

	// Log without acquiring lock again (we already hold it)
	l.logWithoutLock(LogLevelInfo, "File logging enabled", nil, "log_file", logPath)

	return nil
}

// DisableFileLogging disables file logging
func (l *NetworkMapperLogger) DisableFileLogging() {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.logFile != nil {
		l.logFile.Close()
		l.logFile = nil
	}

	l.enableFile = false

	// Remove file writer from the list (keep only console writers)
	newWriters := make([]io.Writer, 0)
	for _, writer := range l.writers {
		if writer != l.logFile {
			newWriters = append(newWriters, writer)
		}
	}
	l.writers = newWriters
}

// SetLevel sets the minimum log level
func (l *NetworkMapperLogger) SetLevel(level LogLevel) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.level = level
}

// GetLevel returns the current log level
func (l *NetworkMapperLogger) GetLevel() LogLevel {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.level
}

// WithField adds a field to the logger context
func (l *NetworkMapperLogger) WithField(key string, value any) *NetworkMapperLogger {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	newLogger := &NetworkMapperLogger{
		level:      l.level,
		writers:    l.writers,
		component:  l.component,
		fields:     make(map[string]any),
		logFile:    l.logFile,
		enableFile: l.enableFile,
	}

	// Copy existing fields
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	// Add new field
	newLogger.fields[key] = value

	return newLogger
}

// WithFields adds multiple fields to the logger context
func (l *NetworkMapperLogger) WithFields(fields map[string]any) *NetworkMapperLogger {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	newLogger := &NetworkMapperLogger{
		level:      l.level,
		writers:    l.writers,
		component:  l.component,
		fields:     make(map[string]any),
		logFile:    l.logFile,
		enableFile: l.enableFile,
	}

	// Copy existing fields
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	// Add new fields
	for k, v := range fields {
		newLogger.fields[k] = v
	}

	return newLogger
}

// WithError adds an error to the logger context
func (l *NetworkMapperLogger) WithError(err error) *NetworkMapperLogger {
	return l.WithField("error", err)
}

// Debug logs a debug message
func (l *NetworkMapperLogger) Debug(message string, keyvals ...any) {
	l.log(LogLevelDebug, message, nil, keyvals...)
}

// Info logs an info message
func (l *NetworkMapperLogger) Info(message string, keyvals ...any) {
	l.log(LogLevelInfo, message, nil, keyvals...)
}

// Warn logs a warning message
func (l *NetworkMapperLogger) Warn(message string, keyvals ...any) {
	l.log(LogLevelWarn, message, nil, keyvals...)
}

// Error logs an error message
func (l *NetworkMapperLogger) Error(message string, keyvals ...any) {
	l.log(LogLevelError, message, nil, keyvals...)
}

// ErrorWithErr logs an error message with an error object
func (l *NetworkMapperLogger) ErrorWithErr(err error, message string, keyvals ...any) {
	l.log(LogLevelError, message, err, keyvals...)
}

// Fatal logs a fatal message and exits
func (l *NetworkMapperLogger) Fatal(message string, keyvals ...any) {
	l.log(LogLevelFatal, message, nil, keyvals...)
	os.Exit(1)
}

// log is the internal logging method
func (l *NetworkMapperLogger) log(level LogLevel, message string, err error, keyvals ...any) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	// Check if we should log this level
	if level < l.level {
		return
	}

	// Get caller information
	_, file, line, ok := runtime.Caller(2)
	if ok {
		file = filepath.Base(file)
	}

	// Create log entry
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Component: l.component,
		Message:   message,
		Fields:    make(map[string]any),
		Error:     err,
		File:      file,
		Line:      line,
	}

	// Copy context fields
	for k, v := range l.fields {
		entry.Fields[k] = v
	}

	// Add keyval pairs
	for i := 0; i < len(keyvals); i += 2 {
		if i+1 < len(keyvals) {
			key := fmt.Sprintf("%v", keyvals[i])
			entry.Fields[key] = keyvals[i+1]
		}
	}

	// Format and write the log entry
	formatted := l.formatEntry(entry)

	for _, writer := range l.writers {
		fmt.Fprint(writer, formatted)
	}
}

// logWithoutLock is the internal logging method that doesn't acquire mutex (assumes caller holds lock)
func (l *NetworkMapperLogger) logWithoutLock(level LogLevel, message string, err error, keyvals ...any) {
	// Check if we should log this level
	if level < l.level {
		return
	}

	// Get caller information
	_, file, line, ok := runtime.Caller(2)
	if ok {
		file = filepath.Base(file)
	}

	// Create log entry
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Component: l.component,
		Message:   message,
		Fields:    make(map[string]any),
		Error:     err,
		File:      file,
		Line:      line,
	}

	// Copy context fields
	for k, v := range l.fields {
		entry.Fields[k] = v
	}

	// Add keyval pairs
	for i := 0; i < len(keyvals); i += 2 {
		if i+1 < len(keyvals) {
			key := fmt.Sprintf("%v", keyvals[i])
			entry.Fields[key] = keyvals[i+1]
		}
	}

	// Format and write the log entry
	formatted := l.formatEntry(entry)

	for _, writer := range l.writers {
		fmt.Fprint(writer, formatted)
	}
}

// formatEntry formats a log entry for output
func (l *NetworkMapperLogger) formatEntry(entry LogEntry) string {
	var parts []string

	// Timestamp
	timestamp := entry.Timestamp.Format("2006-01-02 15:04:05.000")
	parts = append(parts, timestamp)

	// Level
	parts = append(parts, fmt.Sprintf("[%s]", entry.Level.String()))

	// Component
	if entry.Component != "" {
		parts = append(parts, fmt.Sprintf("[%s]", entry.Component))
	}

	// File and line (for debug and error levels)
	if entry.Level <= LogLevelDebug || entry.Level >= LogLevelError {
		if entry.File != "" {
			parts = append(parts, fmt.Sprintf("[%s:%d]", entry.File, entry.Line))
		}
	}

	// Message
	parts = append(parts, entry.Message)

	// Fields
	if len(entry.Fields) > 0 {
		var fieldParts []string
		for k, v := range entry.Fields {
			fieldParts = append(fieldParts, fmt.Sprintf("%s=%v", k, v))
		}
		if len(fieldParts) > 0 {
			parts = append(parts, fmt.Sprintf("{%s}", strings.Join(fieldParts, ", ")))
		}
	}

	// Error
	if entry.Error != nil {
		parts = append(parts, fmt.Sprintf("error=%v", entry.Error))
	}

	return strings.Join(parts, " ") + "\n"
}

// Close closes the logger and any open files
func (l *NetworkMapperLogger) Close() error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.logFile != nil {
		err := l.logFile.Close()
		l.logFile = nil
		return err
	}

	return nil
}

// ToStandardLogger converts the NetworkMapperLogger to a standard Go logger
func (l *NetworkMapperLogger) ToStandardLogger() *log.Logger {
	return log.New(&loggerWriter{logger: l, level: LogLevelInfo}, "", 0)
}

// loggerWriter adapts NetworkMapperLogger to io.Writer for standard logger compatibility
type loggerWriter struct {
	logger *NetworkMapperLogger
	level  LogLevel
}

func (lw *loggerWriter) Write(p []byte) (n int, err error) {
	message := strings.TrimSpace(string(p))
	lw.logger.log(lw.level, message, nil)
	return len(p), nil
}

// LogScanStart logs the start of a scan operation
func (l *NetworkMapperLogger) LogScanStart(config ScanConfig) {
	l.WithFields(map[string]any{
		"targets":        len(config.Targets),
		"ports":          len(config.Ports),
		"port_ranges":    len(config.PortRanges),
		"scan_type":      config.ScanType.String(),
		"max_threads":    config.MaxThreads,
		"timeout":        config.Timeout,
		"service_detect": config.ServiceDetect,
		"os_detect":      config.OSDetect,
	}).Info("Starting network scan")
}

// LogScanComplete logs the completion of a scan operation
func (l *NetworkMapperLogger) LogScanComplete(result *ScanResult) {
	l.WithFields(map[string]any{
		"hosts_scanned":  result.Statistics.HostsScanned,
		"ports_scanned":  result.Statistics.PortsScanned,
		"open_ports":     result.Statistics.OpenPorts,
		"closed_ports":   result.Statistics.ClosedPorts,
		"filtered_ports": result.Statistics.FilteredPorts,
		"elapsed_time":   result.Statistics.ElapsedTime,
		"scan_rate":      result.Statistics.ScanRate,
	}).Info("Network scan completed")
}

// LogPortScanResult logs the result of scanning a single port
func (l *NetworkMapperLogger) LogPortScanResult(target string, result PortResult) {
	l.WithFields(map[string]any{
		"target":        target,
		"port":          result.Port,
		"protocol":      result.Protocol,
		"state":         result.State.String(),
		"response_time": result.ResponseTime,
		"service_name":  result.Service.Name,
	}).Debug("Port scan result")
}

// LogError logs a NetworkMapperError with appropriate context
func (l *NetworkMapperLogger) LogError(err *NetworkMapperError) {
	logger := l.WithFields(map[string]any{
		"error_type": err.Type,
		"operation":  err.Operation,
		"target":     err.Target,
		"port":       err.Port,
		"retryable":  err.Retryable,
		"timestamp":  err.Timestamp,
	})

	if len(err.Suggestions) > 0 {
		logger = logger.WithField("suggestions", strings.Join(err.Suggestions, "; "))
	}

	if err.Underlying != nil {
		logger = logger.WithError(err.Underlying)
	}

	logger.Error(err.Message)
}

// LogResourceUsage logs current resource usage information
func (l *NetworkMapperLogger) LogResourceUsage(goroutines int, memoryMB float64, openFiles int) {
	l.WithFields(map[string]any{
		"goroutines": goroutines,
		"memory_mb":  memoryMB,
		"open_files": openFiles,
	}).Debug("Resource usage")
}

// LogRetryAttempt logs a retry attempt
func (l *NetworkMapperLogger) LogRetryAttempt(operation, target string, port int, attempt int, maxRetries int, delay time.Duration) {
	l.WithFields(map[string]any{
		"operation":   operation,
		"target":      target,
		"port":        port,
		"attempt":     attempt,
		"max_retries": maxRetries,
		"retry_delay": delay,
	}).Warn("Retrying operation")
}

// LogConfigurationIssue logs configuration-related issues
func (l *NetworkMapperLogger) LogConfigurationIssue(issue string, suggestions []string) {
	logger := l.WithField("issue", issue)
	if len(suggestions) > 0 {
		logger = logger.WithField("suggestions", strings.Join(suggestions, "; "))
	}
	logger.Warn("Configuration issue detected")
}

// LogPerformanceMetric logs performance-related metrics
func (l *NetworkMapperLogger) LogPerformanceMetric(metric string, value any, unit string) {
	l.WithFields(map[string]any{
		"metric": metric,
		"value":  value,
		"unit":   unit,
	}).Debug("Performance metric")
}
