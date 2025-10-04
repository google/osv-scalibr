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

// Package manifesttoml extracts Manifest.toml files for Julia projects
package manifesttoml

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/BurntSushi/toml"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the name of the Extractor.
	Name = "julia/manifesttoml"
)

var shaPattern = regexp.MustCompile("^[0-9a-f]{40}$")

type juliaManifestDependency struct {
	Version     string   `toml:"version"`
	GitTreeSha1 string   `toml:"git-tree-sha1"`
	RepoURL     string   `toml:"repo-url"`
	Deps        []string `toml:"deps"`
}

type juliaManifestPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

type juliaManifestFile struct {
	ManifestFormat string                               `toml:"manifest_format"`
	Dependencies   map[string][]juliaManifestDependency `toml:"deps"`
}

// Extractor extracts Julia packages from Manifest.toml files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// FileRequired returns true if the specified file matches Julia Manifest.toml file patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "Manifest.toml"
}

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// Extract extracts packages from Julia Manifest.toml files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedTomlFile juliaManifestFile

	_, err := toml.NewDecoder(input.Reader).Decode(&parsedTomlFile)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	packages := make([]*extractor.Package, 0, len(parsedTomlFile.Dependencies))

	for name, dependencies := range parsedTomlFile.Dependencies {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{Packages: packages}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		// Take the first dependency entry (Julia typically has one entry per package name)
		if len(dependencies) == 0 {
			continue
		}
		dependency := dependencies[0]

		var srcCode *extractor.SourceCodeIdentifier
		// Check for git-tree-sha1 (40 character hex string)
		if dependency.GitTreeSha1 != "" && shaPattern.MatchString(dependency.GitTreeSha1) {
			srcCode = &extractor.SourceCodeIdentifier{
				Commit: dependency.GitTreeSha1,
				Repo:   dependency.RepoURL, // Include repo-url if available
			}
		}

		// Skip dependencies that have no version (name is always present from map key)
		if dependency.Version == "" {
			continue
		}

		packages = append(packages, &extractor.Package{
			Name:       name,
			Version:    dependency.Version,
			PURLType:   purl.TypeJulia,
			Locations:  []string{input.Path},
			SourceCode: srcCode,
		})
	}

	return inventory.Inventory{Packages: packages}, nil
}

var _ filesystem.Extractor = Extractor{}
