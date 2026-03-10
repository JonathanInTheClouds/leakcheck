package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/JonathanInTheClouds/leakcheck/internal/git"
	"github.com/JonathanInTheClouds/leakcheck/internal/ignore"
	"github.com/JonathanInTheClouds/leakcheck/internal/report"
	"github.com/JonathanInTheClouds/leakcheck/internal/scanner"
)

var Version = "dev"

func main() {
	flag.Usage = usage
	versionFlag := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println("leakcheck version", Version)
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) == 0 {
		args = []string{"scan"}
	}

	if !git.IsGitRepo() {
		fatal("not inside a git repository")
	}

	switch args[0] {
	case "scan":
		runScan(args[1:])
	case "report":
		runReport(args[1:])
	case "ignore":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: leakcheck ignore <rule-id>")
			os.Exit(1)
		}
		runIgnore(args[1])
	case "watch":
		runWatch()
	case "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "✗ Unknown command: %s\n\n", args[0])
		usage()
		os.Exit(1)
	}
}

// --- scan ---

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	staged  := fs.Bool("staged", false, "scan only staged files")
	format  := fs.String("format", "text", "output format: text or json")
	quiet   := fs.Bool("quiet", false, "only print findings, no summary")
	fs.Parse(args)

	repoRoot, err := git.RepoRoot()
	if err != nil {
		fatal(err.Error())
	}

	ignoreList, err := ignore.Load(repoRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ Could not load ignore list: %v\n", err)
		ignoreList, _ = ignore.Load("/nonexistent") // empty list
	}

	var findings []scanner.Finding
	var scannedCommits, scannedFiles int

	if *staged {
		findings, scannedFiles = scanStaged(ignoreList)
	} else {
		findings, scannedCommits, scannedFiles = scanHistory(ignoreList, *quiet)
	}

	summary := &report.Summary{
		Findings:       findings,
		ScannedCommits: scannedCommits,
		ScannedFiles:   scannedFiles,
	}

	report.Print(os.Stdout, summary, report.Format(*format))
	os.Exit(report.ExitCode(summary))
}

func scanHistory(ignoreList *ignore.List, quiet bool) ([]scanner.Finding, int, int) {
	ignored := ignoreList.AsMap()

	commits, err := git.LogCommits()
	if err != nil {
		fatal(err.Error())
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "Scanning %d commits...\n", len(commits))
	}

	var findings []scanner.Finding
	scannedFiles := 0
	seen := make(map[string]bool) // deduplicate findings

	for _, commit := range commits {
		files, err := git.FilesInCommit(commit.Hash)
		if err != nil {
			continue
		}

		for _, file := range files {
			if shouldSkipFile(file) {
				continue
			}

			content, err := git.FileAtCommit(commit.Hash, file)
			if err != nil {
				continue
			}
			scannedFiles++

			for lineNum, line := range strings.Split(content, "\n") {
				lineFindings := scanner.ScanLine(file, lineNum+1, line, ignored)
				for _, f := range lineFindings {
					// Deduplicate — same rule + file + match across commits
					key := fmt.Sprintf("%s:%s:%s", f.RuleID, f.File, f.Match)
					if seen[key] {
						continue
					}
					seen[key] = true
					f.Commit = commit.Hash
					f.Author = commit.Author
					f.Date   = commit.Date
					findings = append(findings, f)
				}
			}
		}
	}

	return findings, len(commits), scannedFiles
}

func scanStaged(ignoreList *ignore.List) ([]scanner.Finding, int) {
	ignored := ignoreList.AsMap()

	files, err := git.StagedFiles()
	if err != nil {
		fatal(err.Error())
	}
	if len(files) == 0 {
		fmt.Println("No staged files.")
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "Scanning %d staged file(s)...\n", len(files))

	var findings []scanner.Finding
	for _, file := range files {
		if shouldSkipFile(file) {
			continue
		}
		content, err := git.StagedFileContent(file)
		if err != nil {
			continue
		}
		for lineNum, line := range strings.Split(content, "\n") {
			findings = append(findings, scanner.ScanLine(file, lineNum+1, line, ignored)...)
		}
	}

	return findings, len(files)
}

// --- report ---

func runReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	format := fs.String("format", "text", "output format: text or json")
	fs.Parse(args)

	repoRoot, _ := git.RepoRoot()
	ignoreList, _ := ignore.Load(repoRoot)

	findings, commits, files := scanHistory(ignoreList, false)
	summary := &report.Summary{
		Findings:       findings,
		ScannedCommits: commits,
		ScannedFiles:   files,
	}
	report.Print(os.Stdout, summary, report.Format(*format))
}

// --- ignore ---

func runIgnore(pattern string) {
	repoRoot, err := git.RepoRoot()
	if err != nil {
		fatal(err.Error())
	}
	ignoreList, err := ignore.Load(repoRoot)
	if err != nil {
		fatal(err.Error())
	}
	if err := ignoreList.Add(pattern); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("✓ Added %q to .leakcheckignore\n", pattern)
}

// --- watch (pre-commit hook) ---

func runWatch() {
	repoRoot, err := git.RepoRoot()
	if err != nil {
		fatal(err.Error())
	}

	hookPath := repoRoot + "/.git/hooks/pre-commit"
	hookContent := `#!/bin/sh
# leakcheck pre-commit hook
leakcheck scan --staged --quiet
if [ $? -ne 0 ]; then
  echo ""
  echo "leakcheck: secrets detected in staged files. Commit aborted."
  echo "Run 'leakcheck scan --staged' for details."
  echo "To bypass: git commit --no-verify"
  exit 1
fi
`
	if err := os.WriteFile(hookPath, []byte(hookContent), 0755); err != nil {
		fatal(fmt.Sprintf("could not install hook: %v", err))
	}
	fmt.Println("✓ Pre-commit hook installed at .git/hooks/pre-commit")
	fmt.Println("  leakcheck will now scan staged files before every commit.")
	fmt.Println("  To uninstall: rm .git/hooks/pre-commit")
}

// --- helpers ---

// shouldSkipFile returns true for binary/generated files we don't want to scan.
func shouldSkipFile(file string) bool {
	skipExts := []string{
		".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
		".pdf", ".zip", ".tar", ".gz", ".bin",
		".exe", ".dll", ".so", ".dylib",
		".lock", ".sum",
	}
	lower := strings.ToLower(file)
	for _, ext := range skipExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func fatal(msg string) {
	fmt.Fprintf(os.Stderr, "✗ %s\n", msg)
	os.Exit(1)
}

func usage() {
	fmt.Print(`leakcheck — scan git history for leaked secrets

Usage:
  leakcheck [command] [flags]

Commands:
  scan              Scan full git history for secrets (default)
  scan --staged     Scan only staged files (use as pre-commit check)
  report            Full report with remediation steps
  ignore <rule-id>  Add a rule ID to .leakcheckignore
  watch             Install as a git pre-commit hook
  help              Show this help

Flags:
  --version         Print version and exit

Scan flags:
  --staged          Scan staged files only
  --format          Output format: text (default) or json
  --quiet           Suppress progress output

Detection rules:
  aws-access-key    AWS Access Key ID (AKIA...)
  aws-secret-key    AWS Secret Access Key
  private-key       RSA/EC/DSA/OpenSSH private keys
  github-token      GitHub Personal Access Tokens
  stripe-key        Stripe API keys (sk_live, pk_live)
  slack-token       Slack tokens (xoxb, xoxp...)
  slack-webhook     Slack webhook URLs
  generic-api-key   Generic API key assignments
  generic-secret    Generic password/secret assignments
  env-file          Committed .env files
  high-entropy      High entropy strings (possible secrets)

Examples:
  leakcheck scan
  leakcheck scan --staged
  leakcheck scan --format json
  leakcheck ignore high-entropy
  leakcheck watch
`)
}
