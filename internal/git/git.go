package git

import (
	"fmt"
	"os/exec"
	"strings"
)

// Commit represents a single git commit.
type Commit struct {
	Hash    string
	Author  string
	Date    string
	Message string
}

// FileContent represents the content of a file at a specific commit.
type FileContent struct {
	Commit   Commit
	File     string
	Contents string
}

// IsGitRepo returns true if the current directory is inside a git repo.
func IsGitRepo() bool {
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	return cmd.Run() == nil
}

// LogCommits returns all commits in the repository.
func LogCommits() ([]Commit, error) {
	out, err := run("git", "log", "--format=%H|%an|%ai|%s")
	if err != nil {
		return nil, fmt.Errorf("could not read git log: %w", err)
	}

	var commits []Commit
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 4)
		if len(parts) < 4 {
			continue
		}
		commits = append(commits, Commit{
			Hash:    parts[0],
			Author:  parts[1],
			Date:    parts[2],
			Message: parts[3],
		})
	}
	return commits, nil
}

// FilesInCommit returns all files changed in a given commit.
func FilesInCommit(hash string) ([]string, error) {
	// Try normal diff-tree first
	out, err := run("git", "diff-tree", "--no-commit-id", "-r", "--name-only", hash)
	if err != nil || strings.TrimSpace(out) == "" {
		// Fall back to ls-tree for root commit (no parent)
		out, err = run("git", "ls-tree", "-r", "--name-only", hash)
		if err != nil {
			return nil, err
		}
	}
	var files []string
	for _, f := range strings.Split(strings.TrimSpace(out), "\n") {
		if f != "" {
			files = append(files, f)
		}
	}
	return files, nil
}

// FileAtCommit returns the content of a file at a specific commit.
func FileAtCommit(hash, file string) (string, error) {
	out, err := run("git", "show", fmt.Sprintf("%s:%s", hash, file))
	if err != nil {
		return "", err
	}
	return out, nil
}

// StagedFiles returns the list of files currently staged.
func StagedFiles() ([]string, error) {
	out, err := run("git", "diff", "--cached", "--name-only")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range strings.Split(strings.TrimSpace(out), "\n") {
		if f != "" {
			files = append(files, f)
		}
	}
	return files, nil
}

// StagedFileContent returns the staged content of a file.
func StagedFileContent(file string) (string, error) {
	return run("git", "show", ":"+file)
}

// RepoRoot returns the root directory of the current git repo.
func RepoRoot() (string, error) {
	out, err := run("git", "rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func run(args ...string) (string, error) {
	cmd := exec.Command(args[0], args[1:]...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}