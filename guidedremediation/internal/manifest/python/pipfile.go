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

package python

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/BurntSushi/toml"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
	"github.com/google/osv-scalibr/log"
)

// Pipfile is a struct that represents the contents of a Pipfile.
type Pipfile struct {
	Packages    map[string]any `toml:"packages"`
	DevPackages map[string]any `toml:"dev-packages"`
}

type pipfileReadWriter struct{}

// GetPipfileReadWriter returns a ReadWriter for Pipfile manifest files.
func GetPipfileReadWriter() (manifest.ReadWriter, error) {
	return pipfileReadWriter{}, nil
}

// System returns the ecosystem of this ReadWriter.
func (r pipfileReadWriter) System() resolve.System {
	return resolve.PyPI
}

// SupportedStrategies returns the remediation strategies supported for this manifest.
func (r pipfileReadWriter) SupportedStrategies() []strategy.Strategy {
	return []strategy.Strategy{strategy.StrategyRelax}
}

// Read parses the manifest from the given file, preserving the order of dependencies.
func (r pipfileReadWriter) Read(path string, fsys scalibrfs.FS) (manifest.Manifest, error) {
	path = filepath.ToSlash(path)
	f, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pipfile Pipfile
	md, err := toml.NewDecoder(f).Decode(&pipfile)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal Pipfile: %w", err)
	}

	var packageKeys []string
	var devPackageKeys []string
	for _, key := range md.Keys() {
		// A key for a dependency will have 2 parts: `[section, name]`
		if len(key) == 2 {
			switch key[0] {
			case "packages":
				packageKeys = append(packageKeys, key[1])
			case "dev-packages":
				devPackageKeys = append(devPackageKeys, key[1])
			}
		}
	}

	allReqs := []resolve.RequirementVersion{}
	groups := make(map[manifest.RequirementKey][]string)

	// Packages
	pkgReqs := parsePipfileDependencies(pipfile.Packages, packageKeys, false)
	allReqs = append(allReqs, pkgReqs...)

	// Dev packages
	devPkgReqs := parsePipfileDependencies(pipfile.DevPackages, devPackageKeys, true)
	allReqs = append(allReqs, devPkgReqs...)
	for _, r := range devPkgReqs {
		key := manifest.RequirementKey(r.PackageKey)
		groups[key] = append(groups[key], "dev")
	}

	return &pythonManifest{
		filePath: path,
		root: resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.PyPI,
					Name:   "rootproject", // Pipfile doesn't have a project name
				},
				VersionType: resolve.Concrete,
				Version:     "1.0.0",
			},
		},
		requirements: allReqs,
		groups:       groups,
	}, nil
}

// parsePipfileDependencies converts a map of dependencies from a Pipfile's [packages] or
// [dev-packages] section into a slice of resolve.RequirementVersion, respecting the original key order.
func parsePipfileDependencies(deps map[string]any, keys []string, dev bool) []resolve.RequirementVersion {
	var reqs []resolve.RequirementVersion
	if deps == nil {
		return reqs
	}

	var dt dep.Type
	if dev {
		dt.AddAttr(dep.Dev, "")
	}
	for _, name := range keys {
		details, ok := deps[name]
		if !ok {
			continue // Should not happen if keys are from metadata
		}
		if constraint, ok := extractVersionConstraint(name, details); ok {
			reqs = append(reqs, resolve.RequirementVersion{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.PyPI,
						Name:   name,
					},
					Version:     constraint,
					VersionType: resolve.Requirement,
				},
				Type: dt,
			})
		}
	}
	return reqs
}

// extractVersionConstraint parses a single dependency entry from a Pipfile.
// It returns the version constraint string and a boolean indicating if parsing was successful.
// It skips over non-version dependencies like git or path references, returning false in those cases.
func extractVersionConstraint(name string, details any) (string, bool) {
	switch v := details.(type) {
	case string:
		return v, true
	case map[string]any:
		if vs, ok := v["version"].(string); ok {
			return vs, true
		} else if _, ok := v["git"]; ok {
			log.Infof("Skipping git dependency in Pipfile for package %q", name)
			return "", false
		} else if _, ok := v["path"]; ok {
			log.Infof("Skipping path dependency in Pipfile for package %q", name)
			return "", false
		}
	default:
		log.Warnf("unsupported dependency format in Pipfile for package %q", name)
		return "", false
	}

	return "", false
}

// Write writes the manifest after applying the patches to outputPath.
func (r pipfileReadWriter) Write(original manifest.Manifest, fsys scalibrfs.FS, patches []result.Patch, outputPath string) error {
	return write(fsys, original.FilePath(), outputPath, patches, updatePipfile)
}

// updatePipfile takes an io.Reader representing the Pipfile
// and a map of package names to their new version constraints, returns the
// file with the updated requirements as a string.
func updatePipfile(reader io.Reader, requirements []TokenizedRequirements) (string, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("error reading requirements: %w", err)
	}
	content := string(data)

	var pipfile Pipfile
	if _, err := toml.Decode(content, &pipfile); err != nil {
		return "", fmt.Errorf("failed to unmarshal Pipfile: %w", err)
	}

	names := make(map[string]bool, len(requirements))
	for _, req := range requirements {
		names[req.Name] = true
	}

	var sb strings.Builder
	for _, line := range strings.SplitAfter(content, "\n") {
		name, ok := dependencyToUpdate(line, names)
		if !ok {
			// This line is not a dependency requirement.
			sb.WriteString(line)
			continue
		}

		detail, ok := pipfile.Packages[name]
		if !ok {
			detail, ok = pipfile.DevPackages[name]
		}
		if !ok {
			// Not a dependency found in packages or dev-packages.
			sb.WriteString(line)
			continue
		}

		oldVersion, ok := extractVersionConstraint(name, detail)
		if !ok {
			// We cannot parse this dependency requirement.
			sb.WriteString(line)
			continue
		}
		newReq, ok := findTokenizedRequirement(requirements, name, tokenizeRequirement(oldVersion))
		if !ok {
			// We cannot find the new requirement.
			sb.WriteString(line)
			continue
		}

		newLine := strings.Replace(line, "\""+oldVersion+"\"", "\""+formatConstraints(newReq, false)+"\"", 1)
		sb.WriteString(newLine)
	}

	return sb.String(), nil
}

// dependencyToUpdate checks if the given line contains a dependency that needs to be updated.
// It returns the name of the dependency and true if it needs to be updated, otherwise false.
func dependencyToUpdate(line string, names map[string]bool) (string, bool) {
	trimmedLine := strings.TrimSpace(line)
	if trimmedLine == "" {
		return "", false
	}
	if strings.HasPrefix(trimmedLine, "[") || strings.HasPrefix(trimmedLine, "#") {
		return "", false
	}
	parts := strings.SplitN(trimmedLine, "=", 2)
	if len(parts) < 2 {
		return "", false
	}
	name := strings.TrimSpace(parts[0])
	return name, names[name]
}
