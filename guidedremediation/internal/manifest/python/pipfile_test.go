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
	"os"
	"path/filepath"
	"testing"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/result"
)

func TestReadPipfile(t *testing.T) {
	fsys := fs.DirFS("./testdata/pipfile")
	pipfileRW, _ := GetPipfileReadWriter()
	got, err := pipfileRW.Read("Pipfile", fsys)
	if err != nil {
		t.Fatalf("error reading manifest: %v", err)
	}

	var devDepType dep.Type
	devDepType.AddAttr(dep.Dev, "")

	want := testManifest{
		FilePath: "Pipfile",
		Root: resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.PyPI,
					Name:   "rootproject",
				},
				VersionType: resolve.Concrete,
				Version:     "1.0.0",
			},
		},
		System: resolve.PyPI,
		Requirements: []resolve.RequirementVersion{
			{
				VersionKey: resolve.VersionKey{
					PackageKey:  resolve.PackageKey{System: resolve.PyPI, Name: "requests"},
					Version:     "*",
					VersionType: resolve.Requirement,
				},
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey:  resolve.PackageKey{System: resolve.PyPI, Name: "flask"},
					Version:     "==2.0.1",
					VersionType: resolve.Requirement,
				},
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey:  resolve.PackageKey{System: resolve.PyPI, Name: "numpy"},
					Version:     ">=1.20.0,<2.0.0",
					VersionType: resolve.Requirement,
				},
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey:  resolve.PackageKey{System: resolve.PyPI, Name: "pandas"},
					Version:     "~=1.3.0",
					VersionType: resolve.Requirement,
				},
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey:  resolve.PackageKey{System: resolve.PyPI, Name: "django"},
					Version:     ">=3.2",
					VersionType: resolve.Requirement,
				},
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey:  resolve.PackageKey{System: resolve.PyPI, Name: "sentry-sdk"},
					Version:     ">=1.0.0",
					VersionType: resolve.Requirement,
				},
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey:  resolve.PackageKey{System: resolve.PyPI, Name: "gunicorn"},
					Version:     "*",
					VersionType: resolve.Requirement,
				},
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey:  resolve.PackageKey{System: resolve.PyPI, Name: "waitress"},
					Version:     "*",
					VersionType: resolve.Requirement,
				},
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey:  resolve.PackageKey{System: resolve.PyPI, Name: "private-package"},
					Version:     "*",
					VersionType: resolve.Requirement,
				},
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey:  resolve.PackageKey{System: resolve.PyPI, Name: "pytest"},
					Version:     ">=6.0.0",
					VersionType: resolve.Requirement,
				},
				Type: devDepType,
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey:  resolve.PackageKey{System: resolve.PyPI, Name: "black"},
					Version:     "==21.5b2",
					VersionType: resolve.Requirement,
				},
				Type: devDepType,
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey:  resolve.PackageKey{System: resolve.PyPI, Name: "mypy"},
					Version:     "*",
					VersionType: resolve.Requirement,
				},
				Type: devDepType,
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey:  resolve.PackageKey{System: resolve.PyPI, Name: "sphinx"},
					Version:     ">=4.0.0",
					VersionType: resolve.Requirement,
				},
				Type: devDepType,
			},
		},
		Groups: map[manifest.RequirementKey][]string{
			manifest.RequirementKey(resolve.PackageKey{System: resolve.PyPI, Name: "pytest"}): {"dev"},
			manifest.RequirementKey(resolve.PackageKey{System: resolve.PyPI, Name: "black"}):  {"dev"},
			manifest.RequirementKey(resolve.PackageKey{System: resolve.PyPI, Name: "mypy"}):   {"dev"},
			manifest.RequirementKey(resolve.PackageKey{System: resolve.PyPI, Name: "sphinx"}): {"dev"},
		},
	}
	checkManifest(t, "Manifest", got, want)
}

func TestWritePipfile(t *testing.T) {
	rw, _ := GetPipfileReadWriter()
	fsys := fs.DirFS("./testdata/pipfile")
	manif, err := rw.Read("Pipfile", fsys)
	if err != nil {
		t.Fatalf("error reading manifest: %v", err)
	}

	patches := []result.Patch{
		{
			PackageUpdates: []result.PackageUpdate{
				{
					Name:        "flask",
					VersionFrom: "==2.0.1",
					VersionTo:   "==2.0.2",
				},
				{
					Name:        "pandas",
					VersionFrom: "~=1.3.0",
					VersionTo:   ">=1.4.0,<2.0.0",
				},
				{
					Name:        "numpy",
					VersionFrom: ">=1.20.0,<2.0.0",
					VersionTo:   ">=2.0.0,<3.0.0",
				},
				{
					Name:        "black",
					VersionFrom: "==21.5b2",
					VersionTo:   "==22.0.0",
				},
			},
		},
	}
	outDir := t.TempDir()
	outFile := filepath.Join(outDir, "Pipfile")

	if err := rw.Write(manif, fsys, patches, outFile); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read got Pipfile: %v", err)
	}
	want, err := os.ReadFile(filepath.Join("./testdata/pipfile", "want.Pipfile"))
	if err != nil {
		t.Fatalf("failed to read want Pipfile: %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Pipfile (-want +got):\n%s", diff)
	}
}
