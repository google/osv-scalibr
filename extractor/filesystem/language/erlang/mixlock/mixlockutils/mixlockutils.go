// mixlockutils/mixlockutils.go
package mixlockutils

import (
	"bufio"
	"fmt"
	"regexp"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/log"
)

var (
	// "name": {:git, repo, "commit-hash", <other comma-separated values> },
	gitDependencyLineRe = regexp.MustCompile(`^ +"([^"]+)": \{:git, +"([^,]+)", +\"([^,]+)\",.+$`)
	// "name": {source, name, "version", "commit-hash", <other comma-separated values> },
	regularDependencyLineRe = regexp.MustCompile(`^ +"([^"]+)": \{([^,]+), +([^,]+), +\"([^,]+)\", +\"([^,]+)\",.+$`)
)

// Package represents a single package parsed from Mix.lock.
type Package struct {
	Name       string
	Version    string
	Locations  []string
	SourceCode string
}

// ParseMixLockFile extracts packages from Erlang Mix.lock files passed through the scan input.
func ParseMixLockFile(input *filesystem.ScanInput) ([]Package, error) {
	scanner := bufio.NewScanner(input.Reader)

	var packages []Package // Changed to []Package, not []*extractor.Inventory

	for scanner.Scan() {
		line := scanner.Text()

		var name, version, commit string

		match := gitDependencyLineRe.FindStringSubmatch(line)
		if match != nil {
			// This is a git dependency line, doesn't have a version info.
			if len(match) < 4 {
				log.Errorf("invalid mix.lock dependency line %q", line)
				continue
			}
			name = match[1]
			commit = match[3]
			version = "" // Git dependency doesn't have a version, so assign empty string
		} else {
			// This is a regular dependency line with both version and commit info.
			match = regularDependencyLineRe.FindStringSubmatch(line)
			if match == nil {
				continue
			}
			if len(match) < 6 {
				log.Errorf("invalid mix.lock dependency line %q", line)
				continue
			}
			name = match[1]
			version = match[4]
			commit = match[5]
		}

		// Appending Package to the packages slice (now a []Package)
		packages = append(packages, Package{
			Name:       name,
			Version:    version,
			Locations:  []string{input.Path},
			SourceCode: commit,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error while scanning %s: %w", input.Path, err)
	}

	return packages, nil
}
