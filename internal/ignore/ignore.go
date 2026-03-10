package ignore

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const ignoreFile = ".leakcheckignore"

// List manages the ignore list for false positives.
type List struct {
	path    string
	entries map[string]bool
}

// Load reads the .leakcheckignore file from the repo root.
func Load(repoRoot string) (*List, error) {
	path := filepath.Join(repoRoot, ignoreFile)
	l := &List{
		path:    path,
		entries: make(map[string]bool),
	}

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return l, nil
	}
	if err != nil {
		return nil, fmt.Errorf("could not open ignore file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		l.entries[line] = true
	}
	return l, scanner.Err()
}

// Add adds a pattern to the ignore list and saves it.
func (l *List) Add(pattern string) error {
	if l.entries[pattern] {
		return fmt.Errorf("%q is already in the ignore list", pattern)
	}
	l.entries[pattern] = true
	return l.save()
}

// Contains returns true if the pattern is in the ignore list.
func (l *List) Contains(pattern string) bool {
	return l.entries[pattern]
}

// All returns all ignored patterns.
func (l *List) All() []string {
	var out []string
	for k := range l.entries {
		out = append(out, k)
	}
	return out
}

// AsMap returns the ignore list as a map for fast lookup.
func (l *List) AsMap() map[string]bool {
	m := make(map[string]bool)
	for k, v := range l.entries {
		m[k] = v
	}
	return m
}

func (l *List) save() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("could not write ignore file: %w", err)
	}
	defer f.Close()

	fmt.Fprintln(f, "# leakcheck ignore file")
	fmt.Fprintln(f, "# Add rule IDs or file patterns to suppress findings")
	fmt.Fprintln(f, "# Example: aws-access-key")
	fmt.Fprintln(f, "#          .env.test")
	fmt.Fprintln(f)
	for k := range l.entries {
		fmt.Fprintln(f, k)
	}
	return nil
}
