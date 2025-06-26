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
	"path/filepath"
	"slices"

	"deps.dev/util/pypi"
	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
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
	// TODO(#853): implement this function
	return nil
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
func GetReadWriter() manifest.ReadWriter {
	return readWriter{}
}

// System returns the ecosystem of this ReadWriter.
func (r readWriter) System() resolve.System {
	return resolve.PyPI
}

// SupportedStrategies returns the remediation strategies supported for this manifest.
func (r readWriter) SupportedStrategies() []strategy.Strategy {
	// TODO(#853): add relax and in-place strategy
	return []strategy.Strategy{}
}

// Read parses the manifest from the given file.
func (r readWriter) Read(path string, fsys scalibrfs.FS) (manifest.Manifest, error) {
	path = filepath.ToSlash(path)
	f, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ctx := context.Background()
	inv, err := requirements.NewDefault().Extract(ctx, &filesystem.ScanInput{
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
					Name:   "myproject",
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
	// TODO(#853): implement the writer
	return nil
}
