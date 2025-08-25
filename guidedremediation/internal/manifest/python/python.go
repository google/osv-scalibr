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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"deps.dev/util/resolve"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/result"
)

type pythonManifest struct {
	filePath     string
	root         resolve.Version
	requirements []resolve.RequirementVersion
	groups       map[manifest.RequirementKey][]string
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
	return m.groups
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
					version:  strings.TrimSpace(constraint[len(op):]),
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

// replaceRequirement takes a full requirement string and replaces its version
// specifier with a new one. It preserves the package name, surrounding whitespace,
// and any post-requirement markers (e.g. comments or environment markers).
func replaceRequirement(req string, newReq []VersionConstraint) string {
	var sb strings.Builder
	opIndex := findFirstOperatorIndex(req)
	if opIndex < 0 {
		// No operator is found.
		return req
	}
	sb.WriteString(req[:opIndex])

	// If the byte before the operator is a space, assume space is needed when constructing requirements.
	extraSpace := req[opIndex-1] == ' '
	sb.WriteString(formatConstraints(newReq, extraSpace))

	index := strings.Index(req, ";")
	if index < 0 {
		index = strings.Index(req, "#")
	}
	if index >= 0 {
		for i := index - 1; i >= 0; i-- {
			// Copy the space between requirements and post-requirements.
			if req[i] != ' ' {
				break
			}
			sb.WriteByte(' ')
		}
		sb.WriteString(req[index:])
	} else {
		// Copy space characters if nothing meaningful is found.
		spaceIndex := -1
		for i := len(req) - 1; i >= 0; i-- {
			if !unicode.IsSpace(rune(req[i])) {
				spaceIndex = i
				break
			}
		}
		sb.WriteString(req[spaceIndex+1:])
	}
	return sb.String()
}

// TokenizedRequirements represents a change from one version constraint to another,
// with each constraint broken down into a slice of VersionConstraint structs.
type TokenizedRequirements struct {
	Name        string
	VersionFrom []VersionConstraint
	VersionTo   []VersionConstraint
}

// findTokenizedRequirement searches for a requirement in a slice of TokenizedRequirements
// that matches the given package name and original version constraints.
func findTokenizedRequirement(requirements []TokenizedRequirements, name string, from []VersionConstraint) ([]VersionConstraint, bool) {
	for _, req := range requirements {
		if name == req.Name && slices.Equal(req.VersionFrom, from) {
			return req.VersionTo, true
		}
	}
	return nil, false
}

// write is a generic helper function that orchestrates the patching of a manifest file.
// It reads the original manifest from inputPath, processes the required changes from patches,
// and delegates the content modification to the provided update function. The resulting
// patched content is then written to outputPath.
func write(fsys scalibrfs.FS, inputPath, outputPath string, patches []result.Patch, update func(reader io.Reader, requirements []TokenizedRequirements) (string, error)) error {
	f, err := fsys.Open(inputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	requirements := []TokenizedRequirements{}
	for _, patch := range patches {
		for _, req := range patch.PackageUpdates {
			requirements = append(requirements, TokenizedRequirements{
				Name:        req.Name,
				VersionFrom: tokenizeRequirement(req.VersionFrom),
				VersionTo:   tokenizeRequirement(req.VersionTo),
			})
		}
	}

	output, err := update(f, requirements)
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
