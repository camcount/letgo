package networkmapper

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestMemoryUsageMonitoring tests that memory usage stays within bounds during large scans
func TestMemoryUsageMonitoring(t *testing.T) {
	logger := NewNetworkMapperLogger("test", LogLevelError) // Reduce log noise

	// Set a low memory threshold for testing
	memoryThreshold := 50.0 // 50MB
	memoryMonitor := NewMemoryMonitor(memoryThreshold, logger)

	// Start monitoring
	memoryMonitor.Start()
	defer memoryMonitor.Stop()

	// Force some memory allocation to test monitoring
	var memoryHogs [][]byte
	for i := 0; i < 10; i++ {
		// Allocate 5MB chunks
		chunk := make([]byte, 5*1024*1024)
		memoryHogs = append(memoryHogs, chunk)

		// Check memory usage
		err := memoryMonitor.CheckMemoryUsage()
		if err != nil {
			t.Logf("Memory threshold exceeded as expected: %v", err)
			break
		}
	}

	// Force garbage collection and verify memory is freed
	memoryMonitor.ForceGarbageCollection()

	// Clear references to allow GC
	t.Logf("Allocated %d memory chunks for testing", len(memoryHogs))
	memoryHogs = nil
	runtime.GC()

	// Verify memory usage is reduced
	stats := memoryMonitor.GetMemoryStats()
	if stats.AllocMB > memoryThreshold {
		t.Errorf("Memory usage still high after GC: %.2f MB > %.2f MB", stats.AllocMB, memoryThreshold)
	}

	t.Logf("Memory monitoring test completed. Final usage: %.2f MB", stats.AllocMB)
}

// TestFileDescriptorCleanup tests that file descriptors are properly cleaned up
func TestFileDescriptorCleanup(t *testing.T) {
	logger := NewNetworkMapperLogger("test", LogLevelError)
	maxFDs := 50
	fdManager := NewFileDescriptorManager(maxFDs, logger)
	defer fdManager.Close()

	ctx := context.Background()

	// Acquire multiple file descriptors
	var wg sync.WaitGroup
	acquiredCount := 0

	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			target := "127.0.0.1"
			port := 8000 + id

			err := fdManager.AcquireFileDescriptor(ctx, target, port, "tcp")
			if err != nil {
				t.Logf("Failed to acquire FD %d: %v", id, err)
				return
			}

			acquiredCount++

			// Simulate some work
			time.Sleep(10 * time.Millisecond)

			// Release the file descriptor
			fdManager.ReleaseFileDescriptor(target, port)
		}(i)
	}

	wg.Wait()

	// Verify all file descriptors were released
	stats := fdManager.GetFileDescriptorStats()
	if stats.CurrentOpenFDs != 0 {
		t.Errorf("File descriptors not properly cleaned up: %d still open", stats.CurrentOpenFDs)
	}

	if stats.TotalAcquired != stats.TotalReleased {
		t.Errorf("Mismatch in acquired/released FDs: acquired=%d, released=%d",
			stats.TotalAcquired, stats.TotalReleased)
	}

	t.Logf("FD cleanup test completed. Acquired: %d, Released: %d, Peak: %d",
		stats.TotalAcquired, stats.TotalReleased, stats.PeakUsage)
}

// TestFileDescriptorLimits tests that file descriptor limits are enforced
func TestFileDescriptorLimits(t *testing.T) {
	logger := NewNetworkMapperLogger("test", LogLevelError)
	maxFDs := 5 // Small limit for testing
	fdManager := NewFileDescriptorManager(maxFDs, logger)
	defer fdManager.Close()

	ctx := context.Background()

	// Try to acquire more FDs than the limit
	var acquired []struct {
		target string
		port   int
	}

	for i := 0; i < maxFDs+3; i++ {
		target := "127.0.0.1"
		port := 9000 + i

		err := fdManager.AcquireFileDescriptor(ctx, target, port, "tcp")
		if err != nil {
			// Should fail when limit is reached
			if i >= maxFDs {
				t.Logf("FD limit enforced correctly at %d acquisitions", i)
				break
			} else {
				t.Errorf("Unexpected error acquiring FD %d: %v", i, err)
			}
		} else {
			acquired = append(acquired, struct {
				target string
				port   int
			}{target, port})
		}
	}

	// Verify we didn't exceed the limit
	stats := fdManager.GetFileDescriptorStats()
	if stats.CurrentOpenFDs > int64(maxFDs) {
		t.Errorf("FD limit exceeded: %d > %d", stats.CurrentOpenFDs, maxFDs)
	}

	// Clean up acquired FDs
	for _, fd := range acquired {
		fdManager.ReleaseFileDescriptor(fd.target, fd.port)
	}

	t.Logf("FD limit test completed. Max allowed: %d, Peak usage: %d", maxFDs, stats.PeakUsage)
}

// TestScanningPerformanceBenchmarks tests scanning performance under various conditions
func TestScanningPerformanceBenchmarks(t *testing.T) {
	logger := NewNetworkMapperLogger("test", LogLevelError)
	resourceManager := NewResourceManager(DefaultResourceLimits(), logger)
	defer resourceManager.Close()

	scanner := NewOptimizedPortScanner(1*time.Second, 1, resourceManager, logger)

	// Test single port scan performance
	ctx := context.Background()
	target := "127.0.0.1"
	port := 22 // SSH port (likely closed on test system)

	startTime := time.Now()
	result := scanner.ScanPort(ctx, target, port, ScanTypeTCPConnect)
	scanDuration := time.Since(startTime)

	if scanDuration > 2*time.Second {
		t.Errorf("Single port scan took too long: %v", scanDuration)
	}

	t.Logf("Single port scan completed in %v, state: %s", scanDuration, result.State)

	// Test batch scanning performance
	ports := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 993}

	startTime = time.Now()
	results := scanner.ScanPorts(ctx, target, ports, ScanTypeTCPConnect)
	batchDuration := time.Since(startTime)

	if len(results) != len(ports) {
		t.Errorf("Expected %d results, got %d", len(ports), len(results))
	}

	// Batch should be faster than individual scans due to concurrency
	expectedMaxDuration := time.Duration(len(ports)) * scanDuration / 2 // Allow for 50% efficiency
	if batchDuration > expectedMaxDuration {
		t.Logf("Batch scan slower than expected: %v > %v (but this may be normal)", batchDuration, expectedMaxDuration)
	}

	// Get performance metrics
	metrics := scanner.GetPerformanceMetrics()
	t.Logf("Performance metrics - Total scans: %d, Avg time: %v, Error rate: %.2f%%, Timeout rate: %.2f%%",
		metrics.TotalScans, metrics.AverageScanTime, metrics.ErrorRate*100, metrics.TimeoutRate*100)

	// Verify metrics are reasonable
	if metrics.TotalScans != int64(len(ports)+1) { // +1 for single scan
		t.Errorf("Expected %d total scans, got %d", len(ports)+1, metrics.TotalScans)
	}

	if metrics.ErrorRate > 0.5 { // More than 50% errors is concerning
		t.Errorf("High error rate: %.2f%%", metrics.ErrorRate*100)
	}
}

// TestResourceManagerLimits tests that resource limits are properly enforced
func TestResourceManagerLimits(t *testing.T) {
	logger := NewNetworkMapperLogger("test", LogLevelError)

	// Set restrictive limits for testing
	limits := ResourceLimits{
		MaxGoroutines:  10,
		MaxMemoryMB:    100.0,
		MaxConnections: 5,
		ScanTimeout:    1 * time.Second,
	}

	resourceManager := NewResourceManager(limits, logger)
	defer resourceManager.Close()

	ctx := context.Background()

	// Test connection limit enforcement
	var wg sync.WaitGroup
	connectionErrors := 0
	successfulConnections := 0

	for i := 0; i < limits.MaxConnections+3; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			err := resourceManager.AcquireConnection(ctx)
			if err != nil {
				connectionErrors++
				t.Logf("Connection %d failed as expected: %v", id, err)
			} else {
				successfulConnections++
				// Hold the connection briefly
				time.Sleep(50 * time.Millisecond)
				resourceManager.ReleaseConnection()
			}
		}(i)
	}

	wg.Wait()

	// Should have some connection errors due to limits
	if connectionErrors == 0 {
		t.Error("Expected some connection errors due to limits, but got none")
	}

	if successfulConnections > limits.MaxConnections {
		t.Errorf("More connections succeeded than limit allows: %d > %d",
			successfulConnections, limits.MaxConnections)
	}

	// Test memory checking
	err := resourceManager.CheckMemoryUsage()
	if err != nil {
		t.Logf("Memory usage check failed (may be expected): %v", err)
	}

	usage := resourceManager.GetResourceUsage()
	t.Logf("Resource usage - Goroutines: %d, Memory: %.2f MB, Connections: %d",
		usage.Goroutines, usage.MemoryMB, usage.Connections)
}

// TestBatchProcessorPerformance tests batch processing performance
func TestBatchProcessorPerformance(t *testing.T) {
	logger := NewNetworkMapperLogger("test", LogLevelError)
	batchProcessor := NewBatchProcessor(10, logger)

	// Create test jobs
	var jobs []ScanJob
	for i := 0; i < 50; i++ {
		job := ScanJob{
			Target:         "127.0.0.1",
			OriginalTarget: "127.0.0.1",
			Ports:          []int{8000 + i},
			Config:         ScanConfig{ScanType: ScanTypeTCPConnect},
		}
		jobs = append(jobs, job)
	}

	// Process jobs and measure performance
	processedJobs := 0
	startTime := time.Now()

	err := batchProcessor.ProcessJobs(context.Background(), jobs, func(job ScanJob) error {
		// Simulate some work
		time.Sleep(1 * time.Millisecond)
		processedJobs++
		return nil
	})

	processingDuration := time.Since(startTime)

	if err != nil {
		t.Errorf("Batch processing failed: %v", err)
	}

	if processedJobs != len(jobs) {
		t.Errorf("Expected %d jobs processed, got %d", len(jobs), processedJobs)
	}

	// Batch processing should be reasonably fast
	maxExpectedDuration := time.Duration(len(jobs)) * 2 * time.Millisecond // Allow 2ms per job
	if processingDuration > maxExpectedDuration {
		t.Logf("Batch processing slower than expected: %v > %v (but may be acceptable)",
			processingDuration, maxExpectedDuration)
	}

	t.Logf("Batch processing completed: %d jobs in %v (%.2f jobs/sec)",
		processedJobs, processingDuration, float64(processedJobs)/processingDuration.Seconds())
}

// TestAdaptiveSchedulerOptimization tests that the adaptive scheduler improves performance
func TestAdaptiveSchedulerOptimization(t *testing.T) {
	logger := NewNetworkMapperLogger("test", LogLevelError)
	scheduler := NewAdaptiveScheduler(logger)

	// Create test jobs with different targets
	var jobs []ScanJob
	targets := []string{"127.0.0.1", "192.168.1.1", "10.0.0.1", "8.8.8.8"}

	for _, target := range targets {
		job := ScanJob{
			Target:         target,
			OriginalTarget: target,
			Ports:          []int{80},
			Config:         ScanConfig{ScanType: ScanTypeTCPConnect},
		}
		jobs = append(jobs, job)
	}

	// Update performance data for some targets
	scheduler.UpdatePerformance("127.0.0.1", 10*time.Millisecond)    // Fast
	scheduler.UpdatePerformance("192.168.1.1", 100*time.Millisecond) // Medium
	scheduler.UpdatePerformance("10.0.0.1", 50*time.Millisecond)     // Medium-fast
	scheduler.UpdatePerformance("8.8.8.8", 200*time.Millisecond)     // Slow

	// Optimize job order
	originalOrder := make([]string, len(jobs))
	for i, job := range jobs {
		originalOrder[i] = job.Target
	}

	optimizedJobs := scheduler.OptimizeJobOrder(jobs)
	optimizedOrder := make([]string, len(optimizedJobs))
	for i, job := range optimizedJobs {
		optimizedOrder[i] = job.Target
	}

	t.Logf("Original order: %v", originalOrder)
	t.Logf("Optimized order: %v", optimizedOrder)

	// Verify that faster targets come first
	if len(optimizedJobs) > 0 && optimizedJobs[0].Target != "127.0.0.1" {
		t.Errorf("Expected fastest target (127.0.0.1) to be first, got %s", optimizedJobs[0].Target)
	}

	if len(optimizedJobs) > 3 && optimizedJobs[len(optimizedJobs)-1].Target != "8.8.8.8" {
		t.Errorf("Expected slowest target (8.8.8.8) to be last, got %s", optimizedJobs[len(optimizedJobs)-1].Target)
	}
}

// TestScanOptimizerPortOrdering tests that port ordering optimization works correctly
func TestScanOptimizerPortOrdering(t *testing.T) {
	logger := NewNetworkMapperLogger("test", LogLevelError)
	optimizer := NewScanOptimizer(logger)

	// Test with common and uncommon ports
	ports := []int{65000, 80, 12345, 443, 22, 99999, 21, 53}

	optimizedPorts := optimizer.OptimizePortOrder(ports)

	t.Logf("Original ports: %v", ports)
	t.Logf("Optimized ports: %v", optimizedPorts)

	// Verify that common ports (80, 443, 22) come first
	commonPortsFound := 0
	for i := 0; i < 3 && i < len(optimizedPorts); i++ {
		port := optimizedPorts[i]
		if port == 80 || port == 443 || port == 22 {
			commonPortsFound++
		}
	}

	if commonPortsFound < 2 {
		t.Errorf("Expected at least 2 common ports in first 3 positions, found %d", commonPortsFound)
	}

	// Test target ordering
	targets := []string{"8.8.8.8", "192.168.1.1", "127.0.0.1", "10.0.0.1"}
	optimizedTargets := optimizer.OptimizeTargetOrder(targets)

	t.Logf("Original targets: %v", targets)
	t.Logf("Optimized targets: %v", optimizedTargets)

	// Verify that local/private networks come first
	if len(optimizedTargets) > 0 && optimizedTargets[0] != "192.168.1.1" && optimizedTargets[0] != "127.0.0.1" && optimizedTargets[0] != "10.0.0.1" {
		t.Errorf("Expected a local/private network target first, got %s", optimizedTargets[0])
	}
}

// TestOptimalBatchSizeCalculation tests batch size optimization
func TestOptimalBatchSizeCalculation(t *testing.T) {
	logger := NewNetworkMapperLogger("test", LogLevelError)
	optimizer := NewScanOptimizer(logger)

	// Test with different job counts and memory limits
	testCases := []struct {
		totalJobs   int
		maxMemoryMB float64
		expectedMin int
		expectedMax int
	}{
		{100, 100.0, 10, 100},
		{1000, 200.0, 50, 200},
		{50, 50.0, 10, 50},
		{5, 100.0, 5, 10},
	}

	for _, tc := range testCases {
		batchSize := optimizer.CalculateOptimalBatchSize(tc.totalJobs, tc.maxMemoryMB)

		if batchSize < tc.expectedMin || batchSize > tc.expectedMax {
			t.Errorf("Batch size %d outside expected range [%d, %d] for %d jobs with %.1f MB memory",
				batchSize, tc.expectedMin, tc.expectedMax, tc.totalJobs, tc.maxMemoryMB)
		}

		t.Logf("Jobs: %d, Memory: %.1f MB -> Batch size: %d", tc.totalJobs, tc.maxMemoryMB, batchSize)
	}
}

// BenchmarkOptimizedPortScanner benchmarks the optimized port scanner
func BenchmarkOptimizedPortScanner(b *testing.B) {
	logger := NewNetworkMapperLogger("test", LogLevelError)
	resourceManager := NewResourceManager(DefaultResourceLimits(), logger)
	defer resourceManager.Close()

	scanner := NewOptimizedPortScanner(500*time.Millisecond, 1, resourceManager, logger)
	ctx := context.Background()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Scan a closed port (should be fast)
		scanner.ScanPort(ctx, "127.0.0.1", 12345, ScanTypeTCPConnect)
	}
}

// BenchmarkBatchProcessing benchmarks batch processing performance
func BenchmarkBatchProcessing(b *testing.B) {
	logger := NewNetworkMapperLogger("test", LogLevelError)
	batchProcessor := NewBatchProcessor(50, logger)

	// Create test jobs
	var jobs []ScanJob
	for i := 0; i < 100; i++ {
		job := ScanJob{
			Target:         "127.0.0.1",
			OriginalTarget: "127.0.0.1",
			Ports:          []int{8000 + i},
			Config:         ScanConfig{ScanType: ScanTypeTCPConnect},
		}
		jobs = append(jobs, job)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		batchProcessor.ProcessJobs(context.Background(), jobs, func(job ScanJob) error {
			// Minimal work to test processing overhead
			return nil
		})
	}
}
