// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package mixlockutils provides common functions for parsing Mix.lock lockfiles.
package mixlockutils

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
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
func ParseMixLockFile(input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	scanner := bufio.NewScanner(input.Reader)

	var inventories []*extractor.Inventory

	for scanner.Scan() {
		line := scanner.Text()

		var name, version, commit string

		// Matching git dependency line
		if match := gitDependencyLineRe.FindStringSubmatch(line); match != nil {
			// This is a git dependency line, doesn't have version info
			if len(match) < 4 {
				log.Errorf("invalid mix.lock dependency line %q", line)
				continue
			}
			name = match[1]
			commit = match[3]
			version = "" // Git dependency doesn't have version info, so empty string
		} else {
			// This is a regular dependency line with both version and commit info
			match := regularDependencyLineRe.FindStringSubmatch(line)
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

		// Directly appending to inventories
		inventories = append(inventories, &extractor.Inventory{
			Name:      name,
			Version:   version,
			Locations: []string{input.Path},
			SourceCode: &extractor.SourceCodeIdentifier{
				Commit: commit,
			},
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error while scanning %s: %w", input.Path, err)
	}

	return inventories, nil
}

// ToPURL converts a package into a PURL.
func ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return &purl.PackageURL{
		Type:    purl.TypeHex,
		Name:    strings.ToLower(i.Name),
		Version: i.Version,
	}
}
