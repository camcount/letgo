package pathtraversal

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ProgressDisplay controls progress display timing
type ProgressDisplay struct {
	lastDisplayTime time.Time
	displayInterval time.Duration
	mu              sync.Mutex
}

// NewProgressDisplay creates a new progress display controller
func NewProgressDisplay(interval time.Duration) *ProgressDisplay {
	return &ProgressDisplay{
		lastDisplayTime: time.Now(),
		displayInterval: interval,
	}
}

// ShouldDisplay returns true if enough time has passed since last display
func (pd *ProgressDisplay) ShouldDisplay() bool {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	if time.Since(pd.lastDisplayTime) > pd.displayInterval {
		pd.lastDisplayTime = time.Now()
		return true
	}
	return false
}

// FormatProgress formats progress for display
func FormatProgress(stats Stats) string {
	percentage := 0
	if stats.TotalPayloads > 0 {
		percentage = int((float64(stats.PayloadsTested) / float64(stats.TotalPayloads)) * 100)
	}

	return fmt.Sprintf("\r[*] Progress: %d%% | Tested: %-7d | Found: %-4d | Time: %v  ",
		percentage, stats.PayloadsTested, stats.VulnerabilitiesFound, stats.ElapsedTime)
}

// FormatResults formats results for console display
func FormatResults(results []PathTraversalResult) string {
	if len(results) == 0 {
		return "No vulnerabilities found.\n"
	}

	// Sort by confidence descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].Confidence > results[j].Confidence
	})

	var output strings.Builder
	output.WriteString(fmt.Sprintf("Found %d potential vulnerabilities:\n\n", len(results)))

	for i, result := range results {
		output.WriteString(fmt.Sprintf("[%d] %s\n", i+1, result.URL))
		output.WriteString(fmt.Sprintf("    Parameter: %s\n", result.Parameter))
		output.WriteString(fmt.Sprintf("    Payload: %s\n", result.Payload))
		output.WriteString(fmt.Sprintf("    Status: %d | Response Size: %d bytes\n", result.StatusCode, result.ResponseSize))
		output.WriteString(fmt.Sprintf("    Indicator: %s | Confidence: %.1f%%\n", result.Indicator, result.Confidence))
		output.WriteString(fmt.Sprintf("    Evidence: %s\n\n", result.Evidence))
	}

	return output.String()
}

// FormatStats formats statistics for console display
func FormatStats(stats Stats) string {
	var output strings.Builder

	output.WriteString(fmt.Sprintf("Elapsed: %v\n", stats.ElapsedTime))
	output.WriteString(fmt.Sprintf("Payloads Tested: %d\n", stats.PayloadsTested))
	output.WriteString(fmt.Sprintf("Vulnerabilities Found: %d\n", stats.VulnerabilitiesFound))
	output.WriteString(fmt.Sprintf("Parameters Scanned: %d / %d\n", stats.ParametersScanned, stats.TotalParameters))
	output.WriteString(fmt.Sprintf("Avg Response Time: %v\n", stats.AvgResponseTime))

	return output.String()
}

// FormatSummary formats a complete scan summary
func FormatSummary(stats Stats, results []PathTraversalResult, duration time.Duration) string {
	var output strings.Builder

	output.WriteString("===== Scan Complete =====\n")
	output.WriteString(fmt.Sprintf("Total Time:           %v\n", duration))
	output.WriteString(fmt.Sprintf("Payloads Tested:      %d\n", stats.PayloadsTested))
	output.WriteString(fmt.Sprintf("Vulnerabilities Found: %d\n\n", stats.VulnerabilitiesFound))

	return output.String()
}

// FormatSummaryDetailed formats a final detailed summary of the scan
func FormatSummaryDetailed(stats Stats, results []PathTraversalResult, duration time.Duration) string {
	var sb strings.Builder

	sb.WriteString("\n╔════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║           PATH TRAVERSAL SCAN SUMMARY                    ║\n")
	sb.WriteString("╠════════════════════════════════════════════════════════════╣\n")

	elapsed := duration.Seconds()
	if elapsed == 0 {
		elapsed = 0.1
	}
	payloadsPerSec := float64(stats.PayloadsTested) / elapsed

	sb.WriteString(fmt.Sprintf("║ Total Payloads Tested: %d (%.1f/sec)                  ║\n",
		stats.PayloadsTested, payloadsPerSec))
	sb.WriteString(fmt.Sprintf("║ Total Vulnerabilities: %d discovered                 ║\n",
		stats.VulnerabilitiesFound))
	sb.WriteString(fmt.Sprintf("║ Total Parameters:      %d scanned                     ║\n",
		stats.TotalParameters))
	sb.WriteString(fmt.Sprintf("║ Scan Duration:         %s                        ║\n",
		formatDuration(duration)))
	sb.WriteString(fmt.Sprintf("║ Avg Response Time:     %s                        ║\n",
		formatDuration(stats.AvgResponseTime)))

	// Calculate success rate
	if stats.PayloadsTested > 0 {
		successRate := (float64(stats.VulnerabilitiesFound) / float64(stats.PayloadsTested)) * 100
		sb.WriteString(fmt.Sprintf("║ Success Rate:          %.2f%%                             ║\n",
			successRate))
	}

	sb.WriteString("╠════════════════════════════════════════════════════════════╣\n")

	// High confidence results
	highConfCount := 0
	for _, r := range results {
		if r.Confidence >= 70 {
			highConfCount++
		}
	}

	sb.WriteString(fmt.Sprintf("║ High Confidence (>70): %d findings                    ║\n", highConfCount))
	sb.WriteString("╚════════════════════════════════════════════════════════════╝\n")

	return sb.String()
}

// HighConfidenceResults filters results by confidence threshold
func HighConfidenceResults(results []PathTraversalResult, threshold float64) []PathTraversalResult {
	var filtered []PathTraversalResult
	for _, result := range results {
		if result.Confidence >= threshold {
			filtered = append(filtered, result)
		}
	}
	return filtered
}

// UniqueVulnerableParameters returns unique parameters found to be vulnerable
func UniqueVulnerableParameters(results []PathTraversalResult) []string {
	seen := make(map[string]bool)
	var unique []string

	for _, result := range results {
		if result.IsVulnerable && !seen[result.Parameter] {
			unique = append(unique, result.Parameter)
			seen[result.Parameter] = true
		}
	}

	sort.Strings(unique)
	return unique
}

// ParameterStats returns statistics broken down by parameter
func ParameterStats(results []PathTraversalResult) map[string]int {
	stats := make(map[string]int)
	for _, result := range results {
		if result.IsVulnerable {
			stats[result.Parameter]++
		}
	}
	return stats
}

// ValidateURL checks if URL is reachable before testing
func ValidateURL(targetURL string) bool {
	normalizedURL := NormalizeURL(targetURL)
	return len(normalizedURL) > 0
}

// SanitizePayload removes dangerous characters while preserving traversal intent
func SanitizePayload(payload string) string {
	// Only keep path traversal relevant characters
	var sanitized strings.Builder
	allowedChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_./:?&#="

	for _, char := range payload {
		if strings.ContainsRune(allowedChars, char) {
			sanitized.WriteRune(char)
		}
	}

	return sanitized.String()
}

// GroupResultsByParameter groups results by parameter name
func GroupResultsByParameter(results []PathTraversalResult) map[string][]PathTraversalResult {
	grouped := make(map[string][]PathTraversalResult)

	for _, result := range results {
		grouped[result.Parameter] = append(grouped[result.Parameter], result)
	}

	return grouped
}

// ExportAsCSV exports results in CSV format
func ExportAsCSV(results []PathTraversalResult) string {
	var output strings.Builder

	// Header
	output.WriteString("URL,Parameter,Payload,StatusCode,ResponseSize,Indicator,Confidence,IsVulnerable,Evidence\n")

	// Data rows
	for _, result := range results {
		output.WriteString(fmt.Sprintf(
			"%s,%s,%s,%d,%d,%s,%.1f,%v,%s\n",
			escapeCSV(result.URL),
			escapeCSV(result.Parameter),
			escapeCSV(result.Payload),
			result.StatusCode,
			result.ResponseSize,
			escapeCSV(result.Indicator),
			result.Confidence,
			result.IsVulnerable,
			escapeCSV(result.Evidence),
		))
	}

	return output.String()
}

// escapeCSV escapes CSV special characters
func escapeCSV(field string) string {
	needsQuote := strings.ContainsAny(field, "\",\n")
	if needsQuote {
		return fmt.Sprintf(`"%s"`, strings.ReplaceAll(field, `"`, `""`))
	}
	return field
}

// CalculateScanPercentage calculates scan completion percentage
func CalculateScanPercentage(stats Stats) int {
	if stats.TotalParameters == 0 {
		return 0
	}
	return int((float64(stats.ParametersScanned) / float64(stats.TotalParameters)) * 100)
}

// EstimateTimeRemaining estimates remaining scan time
func EstimateTimeRemaining(stats Stats) string {
	if stats.ParametersScanned == 0 || stats.AvgResponseTime == 0 {
		return "Calculating..."
	}

	remaining := stats.TotalParameters - stats.ParametersScanned
	estimatedNano := int64(remaining) * stats.AvgResponseTime.Nanoseconds()
	estimatedDuration := fmt.Sprintf("%d seconds", estimatedNano/1e9)

	return estimatedDuration
}

// formatDuration formats a duration nicely
func formatDuration(d time.Duration) string {
	if d.Seconds() < 1 {
		return fmt.Sprintf("%.0fms", d.Seconds()*1000)
	}
	if d.Minutes() < 1 {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%.1fm", d.Minutes())
}
