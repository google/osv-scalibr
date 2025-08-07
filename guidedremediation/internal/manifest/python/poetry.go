// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package python

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"deps.dev/util/pypi"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/BurntSushi/toml"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
	"github.com/google/osv-scalibr/log"
)

// pyProject is a struct that represents the contents of a pyproject.toml file.
type pyProject struct {
	Project project `toml:"project"`
}

// project is a struct that represents the [project] section of a pyproject.toml file.
type project struct {
	Name                 string              `toml:"name"`
	Version              string              `toml:"version"`
	Dependencies         []string            `toml:"dependencies"`
	OptionalDependencies map[string][]string `toml:"optional-dependencies"`
}

type poetryReadWriter struct{}

// GetPoetryReadWriter returns a ReadWriter for requirements.txt manifest files.
func GetPoetryReadWriter() (manifest.ReadWriter, error) {
	return poetryReadWriter{}, nil
}

// System returns the ecosystem of this ReadWriter.
func (r poetryReadWriter) System() resolve.System {
	return resolve.PyPI
}

// SupportedStrategies returns the remediation strategies supported for this manifest.
func (r poetryReadWriter) SupportedStrategies() []strategy.Strategy {
	return []strategy.Strategy{strategy.StrategyRelax}
}

// parseDependencies parses a slice of dependency strings from a pyproject.toml file,
// converting them into a slice of resolve.RequirementVersion.
func parseDependencies(deps []string, optional bool) []resolve.RequirementVersion {
	var reqs []resolve.RequirementVersion
	if deps == nil {
		return reqs
	}

	for _, reqStr := range deps {
		d, err := pypi.ParseDependency(reqStr)
		if err != nil {
			log.Warnf("failed to parse python dependency in pyproject.toml %q: %v", reqStr, err)
			continue
		}

		var dt dep.Type
		if optional {
			dt.AddAttr(dep.Opt, "")
		}
		reqs = append(reqs, resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.PyPI,
					Name:   d.Name,
				},
				Version:     d.Constraint,
				VersionType: resolve.Requirement,
			},
			Type: dt,
		})
	}
	return reqs
}

// Read parses the manifest from the given file.
func (r poetryReadWriter) Read(path string, fsys scalibrfs.FS) (manifest.Manifest, error) {
	path = filepath.ToSlash(path)
	f, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var proj pyProject
	if _, err := toml.NewDecoder(f).Decode(&proj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pyproject.toml: %w", err)
	}

	allReqs := []resolve.RequirementVersion{}
	groups := make(map[manifest.RequirementKey][]string)

	// Dependencies
	allReqs = append(allReqs, parseDependencies(proj.Project.Dependencies, false)...)

	// Optional dependencies
	for groupName, deps := range proj.Project.OptionalDependencies {
		groupReqs := parseDependencies(deps, true)
		allReqs = append(allReqs, groupReqs...)
		for _, r := range groupReqs {
			key := manifest.RequirementKey(r.VersionKey.PackageKey)
			groups[key] = append(groups[key], groupName)
		}
	}

	return &pythonManifest{
		filePath: path,
		root: resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.PyPI,
					Name:   proj.Project.Name,
				},
				VersionType: resolve.Concrete,
				Version:     proj.Project.Version,
			},
		},
		requirements: allReqs,
		groups:       groups,
	}, nil
}

// Write writes the manifest after applying the patches to outputPath.
func (r poetryReadWriter) Write(original manifest.Manifest, fsys scalibrfs.FS, patches []result.Patch, outputPath string) error {
	return write(fsys, original.FilePath(), outputPath, patches, updatePyproject)
}

// updatePyproject takes an io.Reader representing the pyproject.toml file
// and a map of package names to their new version constraints, returns the
// file with the updated requirements as a string.
func updatePyproject(reader io.Reader, requirements map[string][]VersionConstraint) (string, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("error reading requirements: %w", err)
	}

	var sb strings.Builder
	inProjectSection := false
	inOptionalDepsSection := false
	inDepArray := false
	for _, line := range strings.SplitAfter(string(data), "\n") {
		trimmedLine := strings.TrimSpace(line)

		// Update current section.
		if strings.HasPrefix(trimmedLine, "[") && strings.HasSuffix(trimmedLine, "]") {
			inProjectSection = trimmedLine == "[project]"
			inOptionalDepsSection = trimmedLine == "[project.optional-dependencies]"
			inDepArray = false // Reset when section changes.
		}

		// Check if we are entering a dependency array.
		if !inDepArray {
			// `dependencies` in `[project]` or any key in `[project.optional-dependencies]`.
			if (inProjectSection && strings.HasPrefix(trimmedLine, "dependencies =")) ||
				(inOptionalDepsSection && strings.Contains(trimmedLine, "=")) {
				if strings.Contains(line, "[") {
					inDepArray = true
				}
			}
		}

		if !inDepArray {
			// We don't need to touch non-dependency lines.
			sb.WriteString(line)
			continue
		}

		start := strings.Index(line, `"`)
		if start < 0 {
			// Requirement not found
			sb.WriteString(line)
			continue
		}

		end := strings.Index(line[start+1:], `"`)
		if end < 0 {
			// Closing quote is not found
			sb.WriteString(line)
			continue
		}

		reqStr := line[start+1 : start+1+end]
		d, err := pypi.ParseDependency(reqStr)
		if err != nil {
			log.Warnf("failed to parse Python dependency %s: %v", reqStr, err)
			sb.WriteString(line)
			continue
		}

		newReq, ok := requirements[d.Name]
		if !ok {
			// We don't need to update the requirement of this dependency.
			sb.WriteString(line)
			continue
		}

		sb.WriteString(line[:start+1])
		sb.WriteString(replaceRequirement(reqStr, newReq))
		sb.WriteString(line[start+end+1:])

		// Check if we are exiting a dependency array.
		if inDepArray && strings.Contains(line, "]") {
			inDepArray = false
		}
	}

	return sb.String(), nil
}
