// Copyright 2025 Google LLC
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

// Package python provides the manifest parsing and writing for Python requirements.txt.
package python

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"deps.dev/util/pypi"
	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
	"github.com/google/osv-scalibr/log"
)

type pythonManifest struct {
	filePath     string
	root         resolve.Version
	requirements []resolve.RequirementVersion
}

// FilePath returns the path to the manifest file.
func (m *pythonManifest) FilePath() string {
	return m.filePath
}

// Root returns the Version representing this package.
func (m *pythonManifest) Root() resolve.Version {
	return m.root
}

// System returns the ecosystem of this manifest.
func (m *pythonManifest) System() resolve.System {
	return resolve.PyPI
}

// Requirements returns all direct requirements (including dev).
func (m *pythonManifest) Requirements() []resolve.RequirementVersion {
	return m.requirements
}

// Groups returns the dependency groups that the direct requirements belong to.
func (m *pythonManifest) Groups() map[manifest.RequirementKey][]string {
	return map[manifest.RequirementKey][]string{}
}

// LocalManifests returns Manifests of any local packages.
func (m *pythonManifest) LocalManifests() []manifest.Manifest {
	return nil
}

// EcosystemSpecific returns any ecosystem-specific information for this manifest.
func (m *pythonManifest) EcosystemSpecific() any {
	return nil
}

// PatchRequirement modifies the manifest's requirements to include the new requirement version.
func (m *pythonManifest) PatchRequirement(req resolve.RequirementVersion) error {
	for i, oldReq := range m.requirements {
		if oldReq.PackageKey == req.PackageKey {
			m.requirements[i] = req
			return nil
		}
	}
	return fmt.Errorf("package %s not found in manifest", req.Name)
}

// Clone returns a copy of this manifest that is safe to modify.
func (m *pythonManifest) Clone() manifest.Manifest {
	clone := &pythonManifest{
		filePath:     m.filePath,
		root:         m.root,
		requirements: slices.Clone(m.requirements),
	}
	clone.root.AttrSet = m.root.AttrSet.Clone()

	return clone
}

type readWriter struct{}

// GetReadWriter returns a ReadWriter for requirements.txt manifest files.
func GetReadWriter() (manifest.ReadWriter, error) {
	return readWriter{}, nil
}

// System returns the ecosystem of this ReadWriter.
func (r readWriter) System() resolve.System {
	return resolve.PyPI
}

// SupportedStrategies returns the remediation strategies supported for this manifest.
func (r readWriter) SupportedStrategies() []strategy.Strategy {
	return []strategy.Strategy{strategy.StrategyRelax}
}

// Read parses the manifest from the given file.
func (r readWriter) Read(path string, fsys scalibrfs.FS) (manifest.Manifest, error) {
	path = filepath.ToSlash(path)
	f, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	inv, err := requirements.NewDefault().Extract(context.Background(), &filesystem.ScanInput{
		FS:     fsys,
		Path:   path,
		Root:   filepath.Dir(path),
		Reader: f,
	})
	if err != nil {
		return nil, err
	}

	var reqs []resolve.RequirementVersion
	for _, pkg := range inv.Packages {
		m := pkg.Metadata.(*requirements.Metadata)
		if len(m.HashCheckingModeValues) > 0 {
			return nil, errors.New("requirements file in hash checking mode not supported as manifest")
		}
		d, err := pypi.ParseDependency(m.Requirement)
		if err != nil {
			return nil, err
		}
		reqs = append(reqs, resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.PyPI,
					Name:   pkg.Name,
				},
				Version:     d.Constraint,
				VersionType: resolve.Requirement,
			},
		})
	}

	return &pythonManifest{
		filePath: path,
		root: resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.PyPI,
					Name:   "rootproject",
				},
				VersionType: resolve.Concrete,
				Version:     "1.0.0",
			},
		},
		requirements: reqs,
	}, nil
}

// Write writes the manifest after applying the patches to outputPath.
func (r readWriter) Write(original manifest.Manifest, fsys scalibrfs.FS, patches []result.Patch, outputPath string) error {
	f, err := fsys.Open(original.FilePath())
	if err != nil {
		return err
	}
	defer f.Close()

	requirements := make(map[string][]VersionConstraint)
	for _, patch := range patches {
		for _, req := range patch.PackageUpdates {
			requirements[req.Name] = tokenizeRequirement(req.VersionTo)
		}
	}

	output, err := updateRequirements(f, requirements)
	if err != nil {
		return err
	}

	// Write the patched manifest to the output path.
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return err
	}

	return nil
}

// Define the possible operators, ordered by length descending
// to ensure correct matching (e.g., "==" before "=" or ">=" before ">").
var operators = []string{
	"==", // Equal
	"!=", // Not equal
	">=", // Greater than or equal
	"<=", // Less than or equal
	"~=", // Compatible release
	">",  // Greater than
	"<",  // Less than
}

// VersionConstraint represents a single parsed requirement constraint,
// consisting of an operator (e.g., "==", ">=") and a version number.
type VersionConstraint struct {
	operator string
	version  string
}

// tokenizeVersionSpecifier takes a single Python version specifier string (e.g., ">=2.32.4,<3.0.0")
// and breaks it down into individual version constraints. Each constraint is
// represented by a VersionConstraint struct.
func tokenizeRequirement(requirement string) []VersionConstraint {
	if requirement == "" {
		return []VersionConstraint{}
	}

	var tokenized []VersionConstraint
	for _, constraint := range strings.Split(requirement, ",") {
		constraint = strings.TrimSpace(constraint)
		if constraint == "" {
			continue
		}

		for _, op := range operators {
			if strings.HasPrefix(constraint, op) {
				tokenized = append(tokenized, VersionConstraint{
					operator: op,
					version:  constraint[len(op):],
				})
				break
			}
		}
	}

	return tokenized
}

// formatConstraints converts a slice of VersionConstraint structs into a
// comma-separated string suitable for a requirements.txt file.
//
// If space is true:
// - A space will be inserted between the operator and the version;
// - A space will be inserted after the comma between constraints.
func formatConstraints(constraints []VersionConstraint, space bool) string {
	if len(constraints) == 0 {
		return ""
	}

	var parts []string
	for _, vc := range constraints {
		if space {
			parts = append(parts, vc.operator+" "+vc.version)
		} else {
			parts = append(parts, vc.operator+vc.version)
		}
	}

	if space {
		return strings.Join(parts, ", ") // Add space after comma
	}
	return strings.Join(parts, ",")
}

// findFirstOperatorIndex finds the index of the first appearance of any operator
// from the given list within a string. It returns -1 if no operator is found.
func findFirstOperatorIndex(s string) int {
	firstIndex := -1

	for _, op := range operators {
		index := strings.Index(s, op)
		if index != -1 {
			// If an operator is found, check if its index is smaller than
			// the current smallest index found so far.
			if firstIndex == -1 || index < firstIndex {
				firstIndex = index
			}
		}
	}
	return firstIndex
}

// updateRequirements takes an io.Reader representing the requirements.txt file
// and a map of package names to their new version constraints, returns the
// file with the updated requirements as a string.
func updateRequirements(reader io.Reader, requirements map[string][]VersionConstraint) (string, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("error reading requirements: %w", err)
	}

	var sb strings.Builder
	for _, line := range strings.SplitAfter(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			sb.WriteString(line)
			continue
		}

		d, err := pypi.ParseDependency(line)
		if err != nil {
			log.Warnf("failed to parse Python dependency %s: %v", line, err)
			sb.WriteString(line)
			continue
		}

		newReq, ok := requirements[d.Name]
		if !ok {
			// We don't need to update the requirement of this dependency.
			sb.WriteString(line)
			continue
		}

		opIndex := findFirstOperatorIndex(line)
		if opIndex < 0 {
			// No operator is found.
			sb.WriteString(line)
			continue
		}
		sb.WriteString(line[:opIndex])

		// If the byte before the operator is a space, assume space is needed when constructing requirements.
		extraSpace := line[opIndex-1] == ' '
		sb.WriteString(formatConstraints(newReq, extraSpace))

		index := strings.Index(line, ";")
		if index < 0 {
			index = strings.Index(line, "#")
		}
		if index >= 0 {
			for i := index - 1; i >= 0; i-- {
				// Copy the space between requirements and post-requirements.
				if line[i] != ' ' {
					break
				}
				sb.WriteByte(' ')
			}
			sb.WriteString(line[index:])
		} else {
			// Copy space characters if nothing meaningful is found.
			spaceIndex := -1
			for i := len(line) - 1; i >= 0; i-- {
				if !unicode.IsSpace(rune(line[i])) {
					spaceIndex = i
					break
				}
			}
			sb.WriteString(line[spaceIndex+1:])
		}
	}

	return sb.String(), nil
}
