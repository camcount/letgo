package networkmapper

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// ErrorType represents different categories of errors
type ErrorType string

const (
	ErrorTypeValidation    ErrorType = "validation"
	ErrorTypeNetwork       ErrorType = "network"
	ErrorTypeTimeout       ErrorType = "timeout"
	ErrorTypeResource      ErrorType = "resource"
	ErrorTypeConfiguration ErrorType = "configuration"
	ErrorTypeInternal      ErrorType = "internal"
	ErrorTypePermission    ErrorType = "permission"
)

// NetworkMapperError is a comprehensive error type for the network mapper
type NetworkMapperError struct {
	Type        ErrorType
	Operation   string
	Target      string
	Port        int
	Message     string
	Underlying  error
	Timestamp   time.Time
	Retryable   bool
	Suggestions []string
}

// Error implements the error interface
func (e *NetworkMapperError) Error() string {
	var parts []string

	if e.Operation != "" {
		parts = append(parts, fmt.Sprintf("operation=%s", e.Operation))
	}

	if e.Target != "" {
		parts = append(parts, fmt.Sprintf("target=%s", e.Target))
	}

	if e.Port > 0 {
		parts = append(parts, fmt.Sprintf("port=%d", e.Port))
	}

	context := ""
	if len(parts) > 0 {
		context = fmt.Sprintf(" [%s]", strings.Join(parts, ", "))
	}

	baseMsg := fmt.Sprintf("%s error%s: %s", e.Type, context, e.Message)

	if e.Underlying != nil {
		baseMsg += fmt.Sprintf(" (caused by: %v)", e.Underlying)
	}

	return baseMsg
}

// Unwrap returns the underlying error for error unwrapping
func (e *NetworkMapperError) Unwrap() error {
	return e.Underlying
}

// IsRetryable returns whether this error should be retried
func (e *NetworkMapperError) IsRetryable() bool {
	return e.Retryable
}

// GetSuggestions returns suggestions for resolving the error
func (e *NetworkMapperError) GetSuggestions() []string {
	return e.Suggestions
}

// NewValidationError creates a new validation error
func NewValidationError(operation, message string, suggestions ...string) *NetworkMapperError {
	return &NetworkMapperError{
		Type:        ErrorTypeValidation,
		Operation:   operation,
		Message:     message,
		Timestamp:   time.Now(),
		Retryable:   false,
		Suggestions: suggestions,
	}
}

// NewNetworkError creates a new network error
func NewNetworkError(operation, target string, port int, underlying error, suggestions ...string) *NetworkMapperError {
	retryable := IsRetryableNetworkError(underlying)

	return &NetworkMapperError{
		Type:        ErrorTypeNetwork,
		Operation:   operation,
		Target:      target,
		Port:        port,
		Message:     "network operation failed",
		Underlying:  underlying,
		Timestamp:   time.Now(),
		Retryable:   retryable,
		Suggestions: suggestions,
	}
}

// NewTimeoutError creates a new timeout error
func NewTimeoutError(operation, target string, port int, timeout time.Duration, suggestions ...string) *NetworkMapperError {
	return &NetworkMapperError{
		Type:        ErrorTypeTimeout,
		Operation:   operation,
		Target:      target,
		Port:        port,
		Message:     fmt.Sprintf("operation timed out after %v", timeout),
		Timestamp:   time.Now(),
		Retryable:   true,
		Suggestions: suggestions,
	}
}

// NewResourceError creates a new resource constraint error
func NewResourceError(operation, message string, suggestions ...string) *NetworkMapperError {
	return &NetworkMapperError{
		Type:        ErrorTypeResource,
		Operation:   operation,
		Message:     message,
		Timestamp:   time.Now(),
		Retryable:   false,
		Suggestions: suggestions,
	}
}

// NewConfigurationError creates a new configuration error
func NewConfigurationError(operation, message string, suggestions ...string) *NetworkMapperError {
	return &NetworkMapperError{
		Type:        ErrorTypeConfiguration,
		Operation:   operation,
		Message:     message,
		Timestamp:   time.Now(),
		Retryable:   false,
		Suggestions: suggestions,
	}
}

// NewPermissionError creates a new permission error
func NewPermissionError(operation, message string, suggestions ...string) *NetworkMapperError {
	return &NetworkMapperError{
		Type:        ErrorTypePermission,
		Operation:   operation,
		Message:     message,
		Timestamp:   time.Now(),
		Retryable:   false,
		Suggestions: suggestions,
	}
}

// IsRetryableNetworkError determines if a network error should be retried
func IsRetryableNetworkError(err error) bool {
	if err == nil {
		return false
	}

	// Check for network errors that are typically retryable
	if netErr, ok := err.(net.Error); ok {
		return netErr.Temporary() || netErr.Timeout()
	}

	// Check for specific error strings that indicate retryable conditions
	errStr := strings.ToLower(err.Error())
	retryableErrors := []string{
		"connection timed out",
		"i/o timeout",
		"network is unreachable",
		"temporary failure in name resolution",
		"connection reset by peer",
		"broken pipe",
		"no buffer space available",
		"resource temporarily unavailable",
	}

	for _, retryableErr := range retryableErrors {
		if strings.Contains(errStr, retryableErr) {
			return true
		}
	}

	// Non-retryable errors
	nonRetryableErrors := []string{
		"connection refused",
		"no route to host",
		"permission denied",
		"operation not permitted",
		"address already in use",
		"invalid argument",
	}

	for _, nonRetryableErr := range nonRetryableErrors {
		if strings.Contains(errStr, nonRetryableErr) {
			return false
		}
	}

	// Default to non-retryable for unknown errors
	return false
}

// WrapError wraps an existing error with additional context
func WrapError(err error, operation, target string, port int) error {
	if err == nil {
		return nil
	}

	// If it's already a NetworkMapperError, just update the context
	if nmErr, ok := err.(*NetworkMapperError); ok {
		if nmErr.Operation == "" {
			nmErr.Operation = operation
		}
		if nmErr.Target == "" {
			nmErr.Target = target
		}
		if nmErr.Port == 0 {
			nmErr.Port = port
		}
		return nmErr
	}

	// Determine error type based on the underlying error
	var errorType ErrorType
	var retryable bool
	var suggestions []string

	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() {
			errorType = ErrorTypeTimeout
			retryable = true
			suggestions = []string{
				"Increase timeout duration",
				"Check network connectivity",
				"Verify target is reachable",
			}
		} else {
			errorType = ErrorTypeNetwork
			retryable = netErr.Temporary()
			suggestions = []string{
				"Check network connectivity",
				"Verify target address is correct",
				"Check firewall settings",
			}
		}
	} else {
		errorType = ErrorTypeInternal
		retryable = false
		suggestions = []string{
			"Check system resources",
			"Verify configuration",
			"Contact support if issue persists",
		}
	}

	return &NetworkMapperError{
		Type:        errorType,
		Operation:   operation,
		Target:      target,
		Port:        port,
		Message:     err.Error(),
		Underlying:  err,
		Timestamp:   time.Now(),
		Retryable:   retryable,
		Suggestions: suggestions,
	}
}

// ErrorRecoveryStrategy defines how to handle different types of errors
type ErrorRecoveryStrategy struct {
	MaxRetries     int
	RetryDelay     time.Duration
	BackoffFactor  float64
	MaxRetryDelay  time.Duration
	FallbackAction func() error
}

// DefaultRecoveryStrategies provides default recovery strategies for different error types
var DefaultRecoveryStrategies = map[ErrorType]ErrorRecoveryStrategy{
	ErrorTypeNetwork: {
		MaxRetries:    3,
		RetryDelay:    100 * time.Millisecond,
		BackoffFactor: 2.0,
		MaxRetryDelay: 5 * time.Second,
	},
	ErrorTypeTimeout: {
		MaxRetries:    2,
		RetryDelay:    500 * time.Millisecond,
		BackoffFactor: 1.5,
		MaxRetryDelay: 10 * time.Second,
	},
	ErrorTypeResource: {
		MaxRetries:    1,
		RetryDelay:    1 * time.Second,
		BackoffFactor: 1.0,
		MaxRetryDelay: 1 * time.Second,
	},
}

// GetRecoveryStrategy returns the appropriate recovery strategy for an error
func GetRecoveryStrategy(err error) ErrorRecoveryStrategy {
	if nmErr, ok := err.(*NetworkMapperError); ok {
		if strategy, exists := DefaultRecoveryStrategies[nmErr.Type]; exists {
			return strategy
		}
	}

	// Default strategy for unknown errors
	return ErrorRecoveryStrategy{
		MaxRetries:    1,
		RetryDelay:    100 * time.Millisecond,
		BackoffFactor: 1.0,
		MaxRetryDelay: 1 * time.Second,
	}
}

// CalculateRetryDelay calculates the delay for a retry attempt with exponential backoff
func CalculateRetryDelay(strategy ErrorRecoveryStrategy, attempt int) time.Duration {
	if attempt <= 0 {
		return strategy.RetryDelay
	}

	delay := strategy.RetryDelay
	for i := 0; i < attempt; i++ {
		delay = time.Duration(float64(delay) * strategy.BackoffFactor)
		if delay > strategy.MaxRetryDelay {
			delay = strategy.MaxRetryDelay
			break
		}
	}

	return delay
}
