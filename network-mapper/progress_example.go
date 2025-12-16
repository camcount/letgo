package networkmapper

import (
	"context"
	"fmt"
	"log"
	"time"
)

// ExampleProgressUsage demonstrates how to use progress monitoring with the network mapper
func ExampleProgressUsage() {
	// Create a console progress display
	consoleDisplay := NewConsoleProgressDisplay(nil)

	// Create a progress callback that displays progress in console
	progressCallback := func(progress ProgressInfo) {
		consoleDisplay.DisplayProgress(progress)
	}

	// Create a progress monitor with the callback
	progressMonitor := NewDefaultProgressMonitor(progressCallback)

	// Create scanner components (these would be real implementations)
	portScanner := NewDefaultPortScanner(5*time.Second, 3, log.Default())
	var serviceDetector ServiceDetector = nil // Optional
	var osFingerprinter OSFingerprinter = nil // Optional
	targetResolver := NewTargetResolver()

	// Create the scanner engine with progress monitoring
	engine := NewConcurrentScannerEngine(
		portScanner,
		serviceDetector,
		osFingerprinter,
		targetResolver,
		progressMonitor,
		log.Default(),
	)

	// Configure scan with progress callback
	config := ScanConfig{
		Targets:       []string{"192.168.1.1", "192.168.1.2"},
		Ports:         []int{22, 80, 443, 8080},
		ScanType:      ScanTypeTCPConnect,
		MaxThreads:    50,
		Timeout:       5 * time.Second,
		ServiceDetect: false,
		OSDetect:      false,
		OnProgress:    progressCallback, // Additional callback for custom handling
	}

	// Start the scan
	ctx := context.Background()
	result, err := engine.Scan(ctx, config)

	// Finish the console display
	consoleDisplay.Finish()

	if err != nil {
		fmt.Printf("Scan failed: %v\n", err)
		return
	}

	// Display final results
	fmt.Printf("\nScan completed successfully!\n")
	fmt.Printf("Hosts scanned: %d\n", result.Statistics.HostsScanned)
	fmt.Printf("Ports scanned: %d\n", result.Statistics.PortsScanned)
	fmt.Printf("Open ports found: %d\n", result.Statistics.OpenPorts)
	fmt.Printf("Total time: %v\n", result.Statistics.ElapsedTime)
	fmt.Printf("Average rate: %.2f ports/second\n", result.Statistics.ScanRate)
}

// ExampleCombinedProgressDisplay demonstrates using multiple progress displays
func ExampleCombinedProgressDisplay() {
	// Create multiple progress displays
	consoleDisplay := NewConsoleProgressDisplay(nil)
	progressBar := NewProgressBarDisplay(50)

	// Create a custom progress callback that logs to file
	fileLogger := log.Default()
	fileCallback := func(progress ProgressInfo) {
		fileLogger.Printf("Progress: %d/%d hosts, %d/%d ports, %.1f%% complete",
			progress.HostsScanned, progress.HostsTotal,
			progress.PortsScanned, progress.PortsTotal,
			float64(progress.PortsScanned)/float64(progress.PortsTotal)*100)
	}

	// Create a callback that shows a progress bar
	barCallback := func(progress ProgressInfo) {
		if progress.PortsTotal > 0 {
			percent := float64(progress.PortsScanned) / float64(progress.PortsTotal) * 100
			bar := progressBar.RenderProgressBar(percent)
			fmt.Printf("\r%s", bar)
		}
	}

	// Combine all displays
	combinedDisplay := NewCombinedProgressDisplay(
		consoleDisplay.DisplayProgress,
		fileCallback,
		barCallback,
	)

	// Create progress monitor with combined display
	progressMonitor := NewDefaultProgressMonitor(combinedDisplay.GetProgressCallback())

	fmt.Printf("Progress monitor created with combined displays\n")
	fmt.Printf("This would be used with the scanner engine as shown in ExampleProgressUsage\n")

	// The progressMonitor would be passed to NewConcurrentScannerEngine
	_ = progressMonitor
}

// ExampleManualProgressTracking demonstrates manual progress tracking
func ExampleManualProgressTracking() {
	// Create a progress monitor
	progressMonitor := NewDefaultProgressMonitor(func(progress ProgressInfo) {
		fmt.Printf("Manual tracking: %d/%d ports (%.1f%%) - Rate: %.1f p/s - ETA: %v\n",
			progress.PortsScanned, progress.PortsTotal,
			float64(progress.PortsScanned)/float64(progress.PortsTotal)*100,
			progress.ScanRate,
			progress.EstimatedTime)
	})

	// Simulate a scan
	totalHosts := 5
	totalPorts := 100

	progressMonitor.Start(totalHosts, totalPorts)

	// Simulate scanning progress
	for host := 1; host <= totalHosts; host++ {
		for port := 1; port <= 20; port++ { // 20 ports per host
			// Simulate scanning time
			time.Sleep(10 * time.Millisecond)

			// Update progress
			hostsScanned := host - 1
			if port == 20 {
				hostsScanned = host // Complete this host
			}
			portsScanned := (host-1)*20 + port

			progressMonitor.UpdateProgress(
				hostsScanned, portsScanned,
				fmt.Sprintf("192.168.1.%d", host), 8000+port,
			)
		}
	}

	progressMonitor.Stop()
	fmt.Println("\nManual progress tracking completed!")
}
