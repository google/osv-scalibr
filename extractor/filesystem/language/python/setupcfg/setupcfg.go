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
	"slices"
	"strings"

	"deps.dev/util/pypi"
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
	// reSection matches an INI section header such as "[options]".
	reSection = regexp.MustCompile(`^\[([^\]]+)\]$`)
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
	// seen deduplicates by normalized name and merges DepGroupVals
	// when a package appears in multiple extras groups.
	seen := map[string]*extractor.Package{}
	var pkgs []*extractor.Package

	addDep := func(raw, group string) {
		pkg := parseDep(raw, group, input.Path)
		if pkg == nil {
			return
		}
		if existing, ok := seen[pkg.Name]; ok {
			// Merge dep group: if this package appears in a new group, append it.
			if group != "" {
				em := existing.Metadata.(*Metadata)
				if !slices.Contains(em.DepGroupVals, group) {
					em.DepGroupVals = append(em.DepGroupVals, group)
				}
			}
			return
		}
		seen[pkg.Name] = pkg
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
		// Do NOT reset inValue here — blank lines and comments can appear
		// between continuation lines in multi-line values.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
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

// normalizeName applies PEP 503 normalization: lowercase and collapse [-_.]+
// runs to a single hyphen.
var reNorm = regexp.MustCompile(`[-_.]+`)

func normalizeName(name string) string {
	return reNorm.ReplaceAllString(strings.ToLower(name), "-")
}

// parseDep parses a single PEP 508 dependency string using pypi.ParseDependency
// and returns a Package, or nil if the entry should be skipped.
func parseDep(raw, group, path string) *extractor.Package {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	// Skip file:, attr:, VCS URLs, local paths, editable installs.
	if reSkippedDep.MatchString(raw) {
		return nil
	}

	// Use the standard PEP 508 parser from deps.dev/util/pypi.
	dep, err := pypi.ParseDependency(raw)
	if err != nil {
		return nil
	}

	name := normalizeName(dep.Name)
	if name == "" {
		return nil
	}

	// Extract version and comparator from the constraint string.
	version, comparator := parseConstraint(dep.Constraint)

	// Store the full original requirement string (preserving extras and markers)
	// so that the transitive dependency enricher can parse it with
	// pypi.ParseDependency for resolution.
	requirement := raw

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
			Requirement:       requirement,
			VersionComparator: comparator,
			DepGroupVals:      groupVals,
		},
	}
}

// parseConstraint extracts version and comparator from a PEP 508 constraint
// string (e.g. ">=2.0", "==1.0", "~=1.24.0"). For compound/unsupported
// constraints (containing commas, wildcards, !=, bare <), it returns empty
// strings to indicate the version cannot be resolved to a single value.
func parseConstraint(constraint string) (version, comparator string) {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" {
		return "", ""
	}

	// Compound constraints or unsupported operators — cannot resolve.
	if strings.Contains(constraint, ",") || strings.Contains(constraint, "*") ||
		strings.Contains(constraint, "!=") {
		return "", ""
	}
	// Bare < without = (e.g. "<2.0")
	if strings.HasPrefix(constraint, "<") && !strings.HasPrefix(constraint, "<=") {
		return "", ""
	}

	separators := []string{"===", "==", ">=", "<=", "~="}
	for _, sep := range separators {
		if strings.HasPrefix(constraint, sep) {
			return strings.TrimSpace(constraint[len(sep):]), sep
		}
	}
	return "", ""
}

var _ filesystem.Extractor = Extractor{}
