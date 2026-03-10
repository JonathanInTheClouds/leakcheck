package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/JonathanInTheClouds/leakcheck/internal/scanner"
)

// Format represents the output format.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// Summary holds scan results.
type Summary struct {
	Findings []scanner.Finding
	ScannedCommits int
	ScannedFiles   int
}

// Print writes the report to the given writer.
func Print(w io.Writer, s *Summary, format Format) {
	switch format {
	case FormatJSON:
		printJSON(w, s)
	default:
		printText(w, s)
	}
}

func printText(w io.Writer, s *Summary) {
	if len(s.Findings) == 0 {
		fmt.Fprintf(w, "✓ No secrets found. Scanned %d commits, %d files.\n",
			s.ScannedCommits, s.ScannedFiles)
		return
	}

	// Group by severity
	high   := filterBySeverity(s.Findings, scanner.SeverityHigh)
	medium := filterBySeverity(s.Findings, scanner.SeverityMedium)
	low    := filterBySeverity(s.Findings, scanner.SeverityLow)

	fmt.Fprintf(w, "\n  leakcheck found %d potential secret%s\n\n",
		len(s.Findings), plural(len(s.Findings)))
	fmt.Fprintf(w, "  Scanned: %d commits, %d files\n\n",
		s.ScannedCommits, s.ScannedFiles)

	if len(high) > 0 {
		fmt.Fprintln(w, "  ── HIGH ──────────────────────────────────────────")
		printFindings(w, high)
	}
	if len(medium) > 0 {
		fmt.Fprintln(w, "  ── MEDIUM ────────────────────────────────────────")
		printFindings(w, medium)
	}
	if len(low) > 0 {
		fmt.Fprintln(w, "  ── LOW ───────────────────────────────────────────")
		printFindings(w, low)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Remediation:")
	fmt.Fprintln(w, "  1. Rotate any exposed credentials immediately")
	fmt.Fprintln(w, "  2. Remove secrets from history: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository")
	fmt.Fprintln(w, "  3. Add false positives to .leakcheckignore")
	fmt.Fprintln(w)
}

func printFindings(w io.Writer, findings []scanner.Finding) {
	for _, f := range findings {
		fmt.Fprintf(w, "\n  ⚠  %s\n", f.Description)
		fmt.Fprintf(w, "     File:   %s (line %d)\n", f.File, f.Line)
		if f.Commit != "" {
			fmt.Fprintf(w, "     Commit: %s — %s (%s)\n", f.Commit[:8], f.Author, f.Date[:10])
		}
		fmt.Fprintf(w, "     Match:  %s\n", f.Match)
		if f.LineContent != "" {
			content := f.LineContent
			if len(content) > 80 {
				content = content[:77] + "..."
			}
			fmt.Fprintf(w, "     Line:   %s\n", content)
		}
		fmt.Fprintf(w, "     Rule:   %s  (suppress with: leakcheck ignore %s)\n", f.RuleID, f.RuleID)
	}
	fmt.Fprintln(w)
}

func printJSON(w io.Writer, s *Summary) {
	out := struct {
		ScannedCommits int               `json:"scanned_commits"`
		ScannedFiles   int               `json:"scanned_files"`
		TotalFindings  int               `json:"total_findings"`
		Findings       []scanner.Finding `json:"findings"`
	}{
		ScannedCommits: s.ScannedCommits,
		ScannedFiles:   s.ScannedFiles,
		TotalFindings:  len(s.Findings),
		Findings:       s.Findings,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

// ExitCode returns 1 if high/medium findings exist, 0 otherwise.
// Used for CI integration.
func ExitCode(s *Summary) int {
	for _, f := range s.Findings {
		if f.Severity == scanner.SeverityHigh || f.Severity == scanner.SeverityMedium {
			return 1
		}
	}
	return 0
}

func filterBySeverity(findings []scanner.Finding, sev scanner.Severity) []scanner.Finding {
	var out []scanner.Finding
	for _, f := range findings {
		if f.Severity == sev {
			out = append(out, f)
		}
	}
	return out
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

var _ = strings.TrimSpace // keep import
