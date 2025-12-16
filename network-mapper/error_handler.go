package networkmapper

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ErrorHandler provides centralized error handling and recovery for network operations
type ErrorHandler struct {
	logger          *NetworkMapperLogger
	resourceManager *ResourceManager
	retryStrategies map[ErrorType]ErrorRecoveryStrategy
	errorStats      *ErrorStatistics
	mutex           sync.RWMutex
}

// ErrorStatistics tracks error occurrences and patterns (internal with mutex)
type ErrorStatistics struct {
	TotalErrors      int64
	ErrorsByType     map[ErrorType]int64
	ErrorsByTarget   map[string]int64
	ErrorsByPort     map[int]int64
	RetriesAttempted int64
	RetriesSucceeded int64
	LastError        *NetworkMapperError
	mutex            sync.RWMutex
}

// ErrorStatisticsSnapshot represents a snapshot of error statistics without mutex
type ErrorStatisticsSnapshot struct {
	TotalErrors      int64
	ErrorsByType     map[ErrorType]int64
	ErrorsByTarget   map[string]int64
	ErrorsByPort     map[int]int64
	RetriesAttempted int64
	RetriesSucceeded int64
	LastError        *NetworkMapperError
}

// NewErrorHandler creates a new error handler
func NewErrorHandler(logger *NetworkMapperLogger, resourceManager *ResourceManager) *ErrorHandler {
	if logger == nil {
		logger = NewNetworkMapperLogger("error-handler", LogLevelInfo)
	}

	return &ErrorHandler{
		logger:          logger,
		resourceManager: resourceManager,
		retryStrategies: DefaultRecoveryStrategies,
		errorStats: &ErrorStatistics{
			ErrorsByType:   make(map[ErrorType]int64),
			ErrorsByTarget: make(map[string]int64),
			ErrorsByPort:   make(map[int]int64),
		},
	}
}

// HandleError processes an error and determines the appropriate response
func (eh *ErrorHandler) HandleError(err error, operation, target string, port int) (*NetworkMapperError, bool) {
	if err == nil {
		return nil, false
	}

	// Convert to NetworkMapperError if needed
	var nmErr *NetworkMapperError
	if existingNmErr, ok := err.(*NetworkMapperError); ok {
		nmErr = existingNmErr
	} else {
		nmErr = &NetworkMapperError{
			Type:       ErrorTypeInternal,
			Operation:  operation,
			Target:     target,
			Port:       port,
			Message:    err.Error(),
			Underlying: err,
			Timestamp:  time.Now(),
			Retryable:  IsRetryableNetworkError(err),
		}
	}

	// Update error statistics
	eh.updateErrorStats(nmErr)

	// Log the error
	eh.logger.LogError(nmErr)

	// Determine if this error should be retried
	shouldRetry := eh.shouldRetryError(nmErr)

	return nmErr, shouldRetry
}

// RetryWithBackoff executes an operation with retry logic and exponential backoff
func (eh *ErrorHandler) RetryWithBackoff(ctx context.Context, operation, target string, port int, fn func() error) error {
	var lastErr error
	strategy := eh.getRetryStrategy(ErrorTypeNetwork) // Default strategy

	for attempt := 0; attempt <= strategy.MaxRetries; attempt++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return NewNetworkError(operation, target, port, ctx.Err(), "Operation was cancelled")
		default:
		}

		// Check resource constraints before retry
		if eh.resourceManager != nil {
			if err := eh.resourceManager.CheckMemoryUsage(); err != nil {
				return WrapError(err, operation, target, port)
			}
		}

		// Execute the operation
		err := fn()
		if err == nil {
			// Success - update retry statistics if this was a retry
			if attempt > 0 {
				eh.updateRetryStats(true)
				eh.logger.Info("Operation succeeded after retry",
					"operation", operation,
					"target", target,
					"port", port,
					"attempt", attempt+1)
			}
			return nil
		}

		// Handle the error
		nmErr, shouldRetry := eh.HandleError(err, operation, target, port)
		lastErr = nmErr

		// Don't retry if we shouldn't or if we've reached max attempts
		if !shouldRetry || attempt >= strategy.MaxRetries {
			eh.updateRetryStats(false)
			break
		}

		// Update strategy based on error type
		if nmErr != nil {
			strategy = eh.getRetryStrategy(nmErr.Type)
		}

		// Calculate retry delay
		delay := CalculateRetryDelay(strategy, attempt)

		// Log retry attempt
		eh.logger.LogRetryAttempt(operation, target, port, attempt+1, strategy.MaxRetries, delay)

		// Wait before retry
		select {
		case <-ctx.Done():
			return NewNetworkError(operation, target, port, ctx.Err(), "Operation was cancelled during retry delay")
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	return lastErr
}

// HandleNetworkOperation wraps a network operation with comprehensive error handling
func (eh *ErrorHandler) HandleNetworkOperation(ctx context.Context, operation, target string, port int, fn func() error) error {
	// Use resource management if available
	if eh.resourceManager != nil {
		return eh.resourceManager.WithConnectionManagement(ctx, operation, target, port, func() error {
			return eh.RetryWithBackoff(ctx, operation, target, port, fn)
		})
	}

	return eh.RetryWithBackoff(ctx, operation, target, port, fn)
}

// HandleValidationError processes validation errors and provides suggestions
func (eh *ErrorHandler) HandleValidationError(err error, context string) error {
	if err == nil {
		return nil
	}

	// If it's already a ValidationError, wrap it with additional context
	if valErr, ok := err.(ValidationError); ok {
		nmErr := NewValidationError(context, valErr.Message)
		nmErr.Target = fmt.Sprintf("%v", valErr.Value)

		// Add context-specific suggestions
		suggestions := eh.getValidationSuggestions(valErr.Field, valErr.Value)
		nmErr.Suggestions = append(nmErr.Suggestions, suggestions...)

		eh.updateErrorStats(nmErr)
		eh.logger.LogError(nmErr)

		return nmErr
	}

	// Wrap other errors as validation errors
	nmErr := NewValidationError(context, err.Error())
	eh.updateErrorStats(nmErr)
	eh.logger.LogError(nmErr)

	return nmErr
}

// HandleResourceError processes resource constraint errors
func (eh *ErrorHandler) HandleResourceError(err error, operation string) error {
	if err == nil {
		return nil
	}

	nmErr := NewResourceError(operation, err.Error())

	// Add resource-specific suggestions
	nmErr.Suggestions = append(nmErr.Suggestions,
		"Reduce scan scope (fewer targets or ports)",
		"Increase resource limits in configuration",
		"Wait for system resources to become available",
		"Close other applications to free resources")

	eh.updateErrorStats(nmErr)
	eh.logger.LogError(nmErr)

	// Force garbage collection if memory-related
	if eh.resourceManager != nil && (err.Error() == "memory" || err.Error() == "out of memory") {
		eh.resourceManager.ForceGarbageCollection()
	}

	return nmErr
}

// GetErrorStatistics returns current error statistics
func (eh *ErrorHandler) GetErrorStatistics() ErrorStatisticsSnapshot {
	eh.errorStats.mutex.RLock()
	defer eh.errorStats.mutex.RUnlock()

	// Create a copy to avoid race conditions
	stats := ErrorStatisticsSnapshot{
		TotalErrors:      eh.errorStats.TotalErrors,
		ErrorsByType:     make(map[ErrorType]int64),
		ErrorsByTarget:   make(map[string]int64),
		ErrorsByPort:     make(map[int]int64),
		RetriesAttempted: eh.errorStats.RetriesAttempted,
		RetriesSucceeded: eh.errorStats.RetriesSucceeded,
		LastError:        eh.errorStats.LastError,
	}

	for k, v := range eh.errorStats.ErrorsByType {
		stats.ErrorsByType[k] = v
	}
	for k, v := range eh.errorStats.ErrorsByTarget {
		stats.ErrorsByTarget[k] = v
	}
	for k, v := range eh.errorStats.ErrorsByPort {
		stats.ErrorsByPort[k] = v
	}

	return stats
}

// SetRetryStrategy sets a custom retry strategy for a specific error type
func (eh *ErrorHandler) SetRetryStrategy(errorType ErrorType, strategy ErrorRecoveryStrategy) {
	eh.mutex.Lock()
	defer eh.mutex.Unlock()
	eh.retryStrategies[errorType] = strategy
}

// shouldRetryError determines if an error should be retried
func (eh *ErrorHandler) shouldRetryError(err *NetworkMapperError) bool {
	if err == nil {
		return false
	}

	// Check if error is marked as retryable
	if !err.Retryable {
		return false
	}

	// Check error frequency for this target/port combination
	key := fmt.Sprintf("%s:%d", err.Target, err.Port)
	eh.errorStats.mutex.RLock()
	errorCount := eh.errorStats.ErrorsByTarget[key]
	eh.errorStats.mutex.RUnlock()

	// Don't retry if we've seen too many errors for this target
	if errorCount > 10 {
		eh.logger.Warn("Too many errors for target, skipping retry",
			"target", err.Target,
			"port", err.Port,
			"error_count", errorCount)
		return false
	}

	return true
}

// getRetryStrategy gets the retry strategy for an error type
func (eh *ErrorHandler) getRetryStrategy(errorType ErrorType) ErrorRecoveryStrategy {
	eh.mutex.RLock()
	defer eh.mutex.RUnlock()

	if strategy, exists := eh.retryStrategies[errorType]; exists {
		return strategy
	}

	// Return default strategy
	return ErrorRecoveryStrategy{
		MaxRetries:    1,
		RetryDelay:    100 * time.Millisecond,
		BackoffFactor: 1.0,
		MaxRetryDelay: 1 * time.Second,
	}
}

// updateErrorStats updates error statistics
func (eh *ErrorHandler) updateErrorStats(err *NetworkMapperError) {
	eh.errorStats.mutex.Lock()
	defer eh.errorStats.mutex.Unlock()

	eh.errorStats.TotalErrors++
	eh.errorStats.ErrorsByType[err.Type]++

	if err.Target != "" {
		key := fmt.Sprintf("%s:%d", err.Target, err.Port)
		eh.errorStats.ErrorsByTarget[key]++
	}

	if err.Port > 0 {
		eh.errorStats.ErrorsByPort[err.Port]++
	}

	eh.errorStats.LastError = err
}

// updateRetryStats updates retry statistics
func (eh *ErrorHandler) updateRetryStats(succeeded bool) {
	eh.errorStats.mutex.Lock()
	defer eh.errorStats.mutex.Unlock()

	eh.errorStats.RetriesAttempted++
	if succeeded {
		eh.errorStats.RetriesSucceeded++
	}
}

// getValidationSuggestions provides context-specific validation suggestions
func (eh *ErrorHandler) getValidationSuggestions(field string, value interface{}) []string {
	switch field {
	case "port":
		return []string{
			"Port must be between 1 and 65535",
			"Common ports: 21 (FTP), 22 (SSH), 80 (HTTP), 443 (HTTPS)",
		}
	case "targets":
		return []string{
			"Use IP addresses (192.168.1.1), hostnames (example.com), or CIDR ranges (192.168.1.0/24)",
			"Separate multiple targets with commas",
		}
	case "timeout":
		return []string{
			"Timeout should be between 100ms and 5 minutes",
			"Use shorter timeouts for faster scans, longer for more reliable results",
		}
	case "max_threads":
		return []string{
			"Reduce thread count if experiencing resource issues",
			"Typical values: 10-100 for local networks, 1-10 for internet scans",
		}
	default:
		return []string{
			"Check the documentation for valid values",
			"Verify the input format and try again",
		}
	}
}

// RecoverFromPanic recovers from panics in network operations
func (eh *ErrorHandler) RecoverFromPanic(operation, target string, port int) {
	if r := recover(); r != nil {
		err := NewNetworkError(operation, target, port,
			fmt.Errorf("panic recovered: %v", r),
			"Check system resources and configuration",
			"Report this issue if it persists")

		eh.updateErrorStats(err)
		eh.logger.LogError(err)
		eh.logger.Error("Panic recovered in network operation",
			"operation", operation,
			"target", target,
			"port", port,
			"panic", r)
	}
}

// GracefulDegradation handles graceful degradation when resources are constrained
func (eh *ErrorHandler) GracefulDegradation(operation string, resourceType string, currentUsage, limit interface{}) error {
	eh.logger.Warn("Resource constraint detected, applying graceful degradation",
		"operation", operation,
		"resource_type", resourceType,
		"current_usage", currentUsage,
		"limit", limit)

	switch resourceType {
	case "memory":
		// Force garbage collection
		if eh.resourceManager != nil {
			eh.resourceManager.ForceGarbageCollection()
		}
		return NewResourceError(operation, "Memory usage high, garbage collection forced")

	case "connections":
		// Reduce connection pool size temporarily
		return NewResourceError(operation, "Connection limit reached, reducing concurrency")

	case "goroutines":
		// Reduce goroutine usage
		return NewResourceError(operation, "Goroutine limit reached, reducing parallelism")

	default:
		return NewResourceError(operation, fmt.Sprintf("Resource limit reached for %s", resourceType))
	}
}
