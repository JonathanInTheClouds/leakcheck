package scanner

import (
	"math"
	"path/filepath"
	"regexp"
	"strings"
)

// Severity represents how serious a finding is.
type Severity string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
)

// Finding represents a detected secret or sensitive value.
type Finding struct {
	RuleID      string
	Description string
	Severity    Severity
	File        string
	Line        int
	LineContent string
	Match       string
	Commit      string
	Author      string
	Date        string
}

// Rule defines a pattern to scan for.
type Rule struct {
	ID          string
	Description string
	Severity    Severity
	Pattern     *regexp.Regexp
	// Optional: entropy threshold (0 = disabled)
	MinEntropy float64
}

// Rules is the full set of detection rules.
var Rules = []Rule{
	{
		ID:          "aws-access-key",
		Description: "AWS Access Key ID",
		Severity:    SeverityHigh,
		Pattern:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	},
	{
		ID:          "aws-secret-key",
		Description: "AWS Secret Access Key",
		Severity:    SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['\"]([0-9a-zA-Z/+]{40})['\"]`),
	},
	{
		ID:          "private-key",
		Description: "Private Key (RSA/EC/DSA)",
		Severity:    SeverityHigh,
		Pattern:     regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
	},
	{
		ID:          "github-token",
		Description: "GitHub Personal Access Token",
		Severity:    SeverityHigh,
		Pattern:     regexp.MustCompile(`(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}`),
	},
	{
		ID:          "stripe-key",
		Description: "Stripe API Key",
		Severity:    SeverityHigh,
		Pattern:     regexp.MustCompile(`(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}`),
	},
	{
		ID:          "slack-token",
		Description: "Slack Token",
		Severity:    SeverityHigh,
		Pattern:     regexp.MustCompile(`xox[baprs]-[0-9A-Za-z\-]{10,}`),
	},
	{
		ID:          "slack-webhook",
		Description: "Slack Webhook URL",
		Severity:    SeverityMedium,
		Pattern:     regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`),
	},
	{
		ID:          "generic-api-key",
		Description: "Generic API Key Assignment",
		Severity:    SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)(api_key|apikey|api-key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?`),
	},
	{
		ID:          "generic-secret",
		Description: "Generic Secret Assignment",
		Severity:    SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"]([^'"]{8,})['\"]`),
	},
	{
		ID:          "env-file",
		Description: "Committed .env file",
		Severity:    SeverityMedium,
		Pattern:     regexp.MustCompile(`.*`), // matches any content — triggered by filename
	},
	{
		ID:          "high-entropy",
		Description: "High Entropy String (possible secret)",
		Severity:    SeverityLow,
		Pattern:     regexp.MustCompile(`['\"]?([A-Za-z0-9+/=_\-]{20,})['\"]?`),
		MinEntropy:  4.5,
	},
}

// ScanLine checks a single line of content against all rules.
// Returns any findings. ruleIDs to skip can be passed as ignored.
func ScanLine(file string, lineNum int, line string, ignored map[string]bool) []Finding {
	var findings []Finding

	// Special case: .env file detection by filename
	base := filepath.Base(file)
	if isEnvFile(base) {
		// Only report the env-file finding once (on line 1)
		if lineNum == 1 && !ignored["env-file"] {
			findings = append(findings, Finding{
				RuleID:      "env-file",
				Description: "Committed .env file",
				Severity:    SeverityMedium,
				File:        file,
				Line:        lineNum,
				LineContent: line,
				Match:       base,
			})
		}
		// Continue scanning contents for secrets inside the .env file
	}

	for _, rule := range Rules {
		if rule.ID == "env-file" {
			continue
		}
		if ignored[rule.ID] {
			continue
		}

		matches := rule.Pattern.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		match := matches[0]
		// Use the full match for display, not a capture group
		if rule.ID == "github-token" || rule.ID == "aws-access-key" {
			match = matches[0]
		} else if len(matches) > 1 {
			match = matches[len(matches)-1]
		}

		// Apply entropy filter for high-entropy rule
		if rule.MinEntropy > 0 {
			if shannonEntropy(match) < rule.MinEntropy {
				continue
			}
		}

		findings = append(findings, Finding{
			RuleID:      rule.ID,
			Description: rule.Description,
			Severity:    rule.Severity,
			File:        file,
			Line:        lineNum,
			LineContent: strings.TrimSpace(line),
			Match:       redact(match),
		})
	}

	return findings
}

// shannonEntropy calculates the Shannon entropy of a string.
// Higher values mean more random/unpredictable content.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	entropy := 0.0
	length := float64(len(s))
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// redact partially masks a secret for safe display.
func redact(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	visible := 4
	return s[:visible] + strings.Repeat("*", len(s)-visible)
}

// isEnvFile returns true if the filename looks like a .env file.
func isEnvFile(name string) bool {
	envFiles := []string{".env", ".env.local", ".env.production", ".env.staging", ".env.development"}
	for _, e := range envFiles {
		if name == e {
			return true
		}
	}
	return strings.HasSuffix(name, ".env")
}