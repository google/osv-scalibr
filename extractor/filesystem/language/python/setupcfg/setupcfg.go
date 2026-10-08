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
	"context"
	"fmt"
	"io"
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
	"gopkg.in/ini.v1"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/setupcfg"
)

var (
	// reValidPkg matches valid PyPI package names per PEP 508,
	// consistent with requirements.go.
	reValidPkg = regexp.MustCompile(`(?i)^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$`)
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

// parse reads a setup.cfg file using gopkg.in/ini.v1 and returns all
// discovered packages.
func parse(input *filesystem.ScanInput) ([]*extractor.Package, error) {
	data, err := io.ReadAll(input.Reader)
	if err != nil {
		return nil, err
	}

	cfg, err := ini.LoadSources(ini.LoadOptions{
		AllowPythonMultilineValues: true,
		IgnoreInlineComment:        true,
	}, data)
	if err != nil {
		return nil, err
	}

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

	// Parse [options] install_requires.
	if sec, err := cfg.GetSection("options"); err == nil {
		if key, err := sec.GetKey("install_requires"); err == nil {
			for line := range strings.SplitSeq(key.String(), "\n") {
				addDep(strings.TrimSpace(line), "")
			}
		}
	}

	// Parse [options.extras_require] — each key is an extras group.
	if sec, err := cfg.GetSection("options.extras_require"); err == nil {
		for _, key := range sec.Keys() {
			group := key.Name()
			for line := range strings.SplitSeq(key.String(), "\n") {
				addDep(strings.TrimSpace(line), group)
			}
		}
	}

	return pkgs, nil
}

// parseDep parses a single PEP 508 dependency string using pypi.ParseDependency
// and returns a Package, or nil if the entry should be skipped.
func parseDep(raw, group, path string) *extractor.Package {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	// Skip URL requirements (e.g. "urllib3 @ https://...").
	if strings.Contains(raw, " @ ") {
		return nil
	}

	// Extract the raw package name (before any version/extras/markers)
	// and validate it using the same regex as requirements.go.
	// This rejects file:, attr:, VCS URLs, paths, editable installs, etc.
	rawName := raw
	if i := strings.IndexAny(raw, " \t[(;<=>!~"); i > 0 {
		rawName = raw[:i]
	}
	if !reValidPkg.MatchString(rawName) {
		return nil
	}

	// Use the standard PEP 508 parser from deps.dev/util/pypi.
	// ParseDependency normalizes names via CanonPackageName.
	dep, err := pypi.ParseDependency(raw)
	if err != nil {
		return nil
	}

	if dep.Name == "" {
		return nil
	}

	// Extract version and comparator from the constraint string.
	version, comparator := parseConstraint(dep.Constraint)

	// Skip if comparator is present but version is empty (e.g. "asdf==").
	if version == "" && comparator != "" {
		return nil
	}

	// Store the full original requirement string (preserving extras and markers)
	// so that the transitive dependency enricher can parse it with
	// pypi.ParseDependency for resolution.
	requirement := raw

	var groupVals []string
	if group != "" {
		groupVals = []string{group}
	}

	return &extractor.Package{
		Name:     dep.Name,
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
