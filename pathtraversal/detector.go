package pathtraversal

import (
	"io"
	"math"
	"strings"
	"time"
)

// ResponseBaseline holds the baseline response data
type ResponseBaseline struct {
	StatusCode   int
	ContentSize  int
	ContentHash  uint64
	ContentType  string
	ResponseTime time.Duration
}

// AnalyzeResponse analyzes a response and determines if path traversal succeeded
func AnalyzeResponse(body []byte, statusCode int, responseTime time.Duration, baselineResp *ResponseBaseline) PathTraversalResult {
	result := PathTraversalResult{
		StatusCode:   statusCode,
		ResponseSize: len(body),
		ResponseTime: responseTime,
		Confidence:   0,
	}

	bodyStr := string(body)

	// Check for file content signatures (highest confidence)
	detected, fileType, confidence := DetectFileContent(bodyStr)
	if detected && confidence > 25 {
		result.IsVulnerable = true
		result.Indicator = "content_match"
		result.Confidence = confidence
		result.Evidence = fileType
		result.Evidence = truncateEvidence(bodyStr, 200)
		return result
	}

	// Check for status code anomalies
	if baselineResp != nil {
		statusDiff := statusCode != baselineResp.StatusCode
		sizeDiff := float64(len(body)) / float64(baselineResp.ContentSize)

		// Successful response where baseline was error
		if statusDiff && statusCode == 200 && baselineResp.StatusCode >= 400 {
			result.Confidence = 75
			result.IsVulnerable = true
			result.Indicator = "status_code_change"
			result.Evidence = "Received 200 OK when baseline returned " + string(rune(baselineResp.StatusCode))
			return result
		}

		// Significant size variance (suggesting file content)
		if baselineResp.ContentSize > 0 && (sizeDiff > 1.5 || sizeDiff < 0.5) {
			confidence := 45 + calculateConfidence(sizeDiff)
			result.Confidence = confidence
			result.Indicator = "size_variance"
			result.Evidence = "Response size differs significantly from baseline"
			if result.Confidence > 50 {
				result.IsVulnerable = true
			}
			return result
		}
	}

	// Check for common error/info patterns
	if hasErrorPatterns(bodyStr) {
		result.Confidence = 35
		result.Indicator = "error_pattern"
		result.Evidence = "Response contains system-level error information"
		return result
	}

	// Check for verbose response that looks like file content
	if looksLikeFileContent(bodyStr) {
		result.Confidence = 40
		result.Indicator = "content_structure"
		result.Evidence = "Response structure suggests file content"
		return result
	}

	return result
}

// hasErrorPatterns detects common error/info disclosure patterns
func hasErrorPatterns(body string) bool {
	patterns := []string{
		"permission denied",
		"no such file",
		"directory not found",
		"access denied",
		"is a directory",
		"cannot open",
		"file not found",
		"bad request",
		"system error",
		"internal error",
		"error opening file",
		"cannot read file",
		"illegal character",
		"path traversal",
	}

	lowerBody := strings.ToLower(body)
	for _, pattern := range patterns {
		if strings.Contains(lowerBody, pattern) {
			return true
		}
	}

	return false
}

// looksLikeFileContent determines if response looks like actual file content
func looksLikeFileContent(body string) bool {
	// Check for common file signatures
	signatures := []string{
		"root:",        // /etc/passwd
		"#!/bin/",      // Shell scripts
		"<?php",        // PHP files
		"<?xml",        // XML files
		"{",            // JSON/JS
		"-----BEGIN",   // SSH keys
		"SELECT",       // SQL
		"CREATE TABLE", // SQL DDL
		"INSERT INTO",  // SQL DML
		"<html",        // HTML
		"[windows]",    // Windows INI
		"DATABASE_URL", // Config files
	}

	lowerBody := strings.ToLower(body)

	signatureMatches := 0
	for _, sig := range signatures {
		if strings.Contains(lowerBody, strings.ToLower(sig)) {
			signatureMatches++
		}
	}

	// If at least 2 signatures match, likely file content
	return signatureMatches >= 2
}

// calculateConfidence calculates confidence based on size ratio
func calculateConfidence(sizeRatio float64) float64 {
	if sizeRatio < 0 {
		return 0
	}

	// More variance = higher confidence up to a point
	deviation := math.Abs(1.0 - sizeRatio)

	if deviation > 3.0 {
		return 50
	}

	return deviation * 16.67 // Max 50 points
}

// GetBaseline fetches and stores baseline response for comparison
func GetBaseline(body io.Reader, statusCode int, responseTime time.Duration) *ResponseBaseline {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return nil
	}

	return &ResponseBaseline{
		StatusCode:   statusCode,
		ContentSize:  len(bodyBytes),
		ResponseTime: responseTime,
	}
}

// DetectByComparison compares current response with baseline
func DetectByComparison(currentBody []byte, currentStatus int, baseline *ResponseBaseline) (vulnerable bool, indicator string, confidence int64) {
	if baseline == nil {
		return false, "", 0
	}

	// Status code changed from error to success
	if baseline.StatusCode >= 400 && currentStatus == 200 {
		return true, "status_recovery", 80
	}

	// Content size dramatically changed
	currentSize := len(currentBody)
	baselineSize := baseline.ContentSize

	if baselineSize > 0 {
		ratio := float64(currentSize) / float64(baselineSize)
		if ratio > 2.0 || ratio < 0.5 {
			return true, "size_variance", 60
		}
	}

	return false, "", 0
}

// truncateEvidence truncates evidence string to avoid huge outputs
func truncateEvidence(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	// Find a good cut point (whitespace if possible)
	cutPoint := maxLen
	for i := maxLen; i > maxLen-50 && i > 0; i-- {
		if s[i] == '\n' || s[i] == ' ' {
			cutPoint = i
			break
		}
	}

	return s[:cutPoint] + "... [truncated]"
}

// CalculateConfidenceScore calculates overall confidence based on multiple factors
func CalculateConfidenceScore(hasContentMatch bool, contentConfidence float64,
	hasStatusAnomaly bool, hasSizeVariance bool, hasErrorPatterns bool) float64 {

	score := 0.0

	if hasContentMatch {
		score += contentConfidence * 1.5 // Highest weight
	}

	if hasStatusAnomaly {
		score += 75 // High confidence
	}

	if hasSizeVariance {
		score += 45 // Medium confidence
	}

	if hasErrorPatterns {
		score += 25 // Low confidence
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}
