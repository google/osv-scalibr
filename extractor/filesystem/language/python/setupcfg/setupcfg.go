// Copyright 2026 Google LLC
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

// Package setupcfg extracts Python dependencies from setup.cfg files.
package setupcfg

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/setupcfg"
)

var (
	// reValidPkg matches valid PyPI package names per PEP 508.
	// https://packaging.python.org/en/latest/specifications/name-normalization/
	reValidPkg = regexp.MustCompile(`(?i)^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$`)
	// reUnsupportedConstraints covers wildcards, less-than, not-equal, and
	// compound constraints that we cannot resolve to a single version.
	reUnsupportedConstraints = regexp.MustCompile(`\*|<[^=]|,|!=`)
	// reExtras strips extras from a requirement string (e.g. "requests[security]").
	reExtras = regexp.MustCompile(`\[[^\[\]]*\]`)
	// reSection matches an INI section header such as "[options]".
	reSection = regexp.MustCompile(`^\[([^\]]+)\]$`)
	// reEnvMarker matches PEP 508 environment markers ("; python_version ...").
	reEnvMarker = regexp.MustCompile(`;.*$`)
	// reSkippedDep matches entries that should be skipped: file://, attr:, VCS
	// URLs, local paths (starting with . or /), and editable installs (-e).
	reSkippedDep = regexp.MustCompile(`(?i)^(file:|attr:|git\+|hg\+|svn\+|bzr\+|\.|/|-e\s)`)
)

// Extractor extracts Python packages from setup.cfg manifests.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the file is named exactly "setup.cfg".
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "setup.cfg"
}

// Extract extracts packages from setup.cfg files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if err := ctx.Err(); err != nil {
		return inventory.Inventory{}, err
	}

	pkgs, err := parse(input)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("setupcfg: %w", err)
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

// parse reads a setup.cfg file and returns all discovered packages.
func parse(input *filesystem.ScanInput) ([]*extractor.Package, error) {
	// seen deduplicates by normalized name.
	seen := map[string]bool{}
	var pkgs []*extractor.Package

	addDep := func(raw, group string) {
		pkg := parseDep(raw, group, input.Path)
		if pkg == nil {
			return
		}
		if seen[pkg.Name] {
			return
		}
		seen[pkg.Name] = true
		pkgs = append(pkgs, pkg)
	}

	// INI parsing state.
	type section int
	const (
		sectionOther     section = iota
		sectionOptions           // [options]
		sectionExtrasReq         // [options.extras_require]
	)

	current := sectionOther
	// currentKey is "install_requires" or an extras name inside extras_require.
	currentKey := ""
	// inValue is true when we are reading continuation lines of a multi-line value.
	inValue := false
	// extrasGroup is the current extras key (treated as dep group).
	extrasGroup := ""

	scanner := bufio.NewScanner(input.Reader)
	for scanner.Scan() {
		line := scanner.Text()

		// Strip inline comments.
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = line[:idx]
		}
		trimmed := strings.TrimSpace(line)

		// Skip blank lines and full-line comments.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			inValue = false
			continue
		}

		// Detect section headers.
		if m := reSection.FindStringSubmatch(trimmed); m != nil {
			sec := strings.ToLower(strings.TrimSpace(m[1]))
			switch sec {
			case "options":
				current = sectionOptions
			case "options.extras_require":
				current = sectionExtrasReq
			default:
				current = sectionOther
			}
			inValue = false
			currentKey = ""
			extrasGroup = ""
			continue
		}

		if current == sectionOther {
			continue
		}

		// Detect new key = value assignment (not a continuation line).
		// Continuation lines start with whitespace.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			inValue = false
			currentKey = ""
			extrasGroup = ""

			if eqIdx := strings.Index(trimmed, "="); eqIdx > 0 {
				key := strings.ToLower(strings.TrimSpace(trimmed[:eqIdx]))
				val := strings.TrimSpace(trimmed[eqIdx+1:])

				switch current {
				case sectionOptions:
					if key == "install_requires" {
						currentKey = key
						inValue = true
						if val != "" {
							addDep(val, "")
						}
					}
				case sectionExtrasReq:
					// Any key is an extras group name (e.g. "dev", "test").
					extrasGroup = key
					currentKey = key
					inValue = true
					if val != "" {
						addDep(val, extrasGroup)
					}
				}
			}
			continue
		}

		// Continuation line — only process if we are inside a known value.
		if inValue && currentKey != "" {
			group := ""
			if current == sectionExtrasReq {
				group = extrasGroup
			}
			addDep(trimmed, group)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return pkgs, nil
}

// parseDep parses a single PEP 508 dependency string and returns a Package, or
// nil if the entry should be skipped (invalid name, unsupported format, etc.).
func parseDep(raw, group, path string) *extractor.Package {
	// Strip environment markers ("; python_version < '3.10'").
	raw = reEnvMarker.ReplaceAllString(raw, "")
	// Strip extras like [security].
	raw = reExtras.ReplaceAllString(raw, "")
	raw = strings.TrimSpace(raw)

	if raw == "" {
		return nil
	}

	// Skip file:, attr:, VCS URLs, local paths, editable installs.
	if reSkippedDep.MatchString(raw) {
		return nil
	}

	name, version, comparator := getLowestVersion(raw)
	// Normalize per PEP 503.
	name = normalizeName(name)
	if name == "" || !reValidPkg.MatchString(name) {
		return nil
	}

	req := name
	if version != "" {
		req = name + comparator + version
	}

	var groupVals []string
	if group != "" {
		groupVals = []string{group}
	}

	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purl.TypePyPi,
		Location: extractor.LocationFromPath(path),
		Metadata: &Metadata{
			Requirement:       req,
			VersionComparator: comparator,
			DepGroupVals:      groupVals,
		},
	}
}

// normalizeName applies PEP 503 normalization: lowercase and collapse [-_.]+
// runs to a single hyphen.
var reNorm = regexp.MustCompile(`[-_.]+`)

func normalizeName(name string) string {
	return reNorm.ReplaceAllString(strings.ToLower(name), "-")
}

// getLowestVersion extracts the package name, version string, and comparator
// from a PEP 508 requirement string, matching the logic in requirements.go.
func getLowestVersion(s string) (name, version, comparator string) {
	if reUnsupportedConstraints.FindString(s) != "" {
		return nameFromRequirement(s), "", ""
	}
	separators := []string{"===", "==", ">=", "<=", "~="}
	for _, sep := range separators {
		if v, after, ok := strings.Cut(s, sep); ok {
			return strings.TrimSpace(v), strings.TrimSpace(after), sep
		}
	}
	return strings.TrimSpace(s), "", ""
}

func nameFromRequirement(s string) string {
	for _, sep := range []string{"===", "==", ">=", "<=", "~=", "!=", "<"} {
		s, _, _ = strings.Cut(s, sep)
	}
	return strings.TrimSpace(s)
}

var _ filesystem.Extractor = Extractor{}
