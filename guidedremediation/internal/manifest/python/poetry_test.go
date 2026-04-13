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

func TestReadPoetry(t *testing.T) {
	fsys := fs.DirFS("./testdata/poetry")
	poetryRW, _ := GetPoetryReadWriter()
	got, err := poetryRW.Read("pyproject.toml", fsys)
	if err != nil {
		t.Fatalf("error reading manifest: %v", err)
	}

	var optionalType dep.Type
	optionalType.AddAttr(dep.Opt, "")

	want := testManifest{
		FilePath: "pyproject.toml",
		Root: resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.PyPI,
					Name:   "my-project",
				},
				VersionType: resolve.Concrete,
				Version:     "1.2.3",
			},
		},
		System: resolve.PyPI,
		Requirements: []resolve.RequirementVersion{
			{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.PyPI,
						Name:   "requests",
					},
					Version:     "~=2.25.1",
					VersionType: resolve.Requirement,
				},
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.PyPI,
						Name:   "numpy",
					},
					Version:     "==1.22.0",
					VersionType: resolve.Requirement,
				},
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.PyPI,
						Name:   "django",
					},
					Version:     ">2.1,<3.0",
					VersionType: resolve.Requirement,
				},
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.PyPI,
						Name:   "django",
					},
					Version:     ">2.0,<3.0",
					VersionType: resolve.Requirement,
				},
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.PyPI,
						Name:   "pytest",
					},
					Version:     ">=6.2.5",
					VersionType: resolve.Requirement,
				},
				Type: optionalType,
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.PyPI,
						Name:   "black",
					},
					Version:     "==22.3.0",
					VersionType: resolve.Requirement,
				},
				Type: optionalType,
			},
		},
		Groups: map[manifest.RequirementKey][]string{
			manifest.RequirementKey(resolve.PackageKey{System: resolve.PyPI, Name: "pytest"}): {"dev"},
			manifest.RequirementKey(resolve.PackageKey{System: resolve.PyPI, Name: "black"}):  {"dev"},
		},
	}
	checkManifest(t, "Manifest", got, want)
}

func TestWritePoetry(t *testing.T) {
	rw, _ := GetPoetryReadWriter()
	fsys := fs.DirFS("./testdata/poetry")
	manif, err := rw.Read("pyproject.toml", fsys)
	if err != nil {
		t.Fatalf("error reading manifest: %v", err)
	}

	patches := []result.Patch{
		{
			PackageUpdates: []result.PackageUpdate{
				{
					Name:        "requests",
					VersionFrom: "~=2.25.1",
					VersionTo:   ">=2.26.0,<3.0.0",
				},
			},
		},
		{
			PackageUpdates: []result.PackageUpdate{
				{
					Name:        "black",
					VersionFrom: "==22.3.0",
					VersionTo:   "==23.0.0",
				},
			},
		},
		{
			PackageUpdates: []result.PackageUpdate{
				{
					Name:        "django",
					VersionFrom: ">2.1,<3.0",
					VersionTo:   ">=3.1,<4.0",
				},
			},
		},
		{
			PackageUpdates: []result.PackageUpdate{
				{
					Name:        "django",
					VersionFrom: ">2.0,<3.0",
					VersionTo:   ">=3.0,<4.0",
				},
			},
		},
	}
	outDir := t.TempDir()
	outFile := filepath.Join(outDir, "pyproject.toml")

	if err := rw.Write(manif, fsys, patches, outFile); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read got pyproject.toml: %v", err)
	}
	want, err := os.ReadFile(filepath.Join("./testdata/poetry", "want.pyproject.toml"))
	if err != nil {
		t.Fatalf("failed to read want pyproject.toml: %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("pyproject.toml (-want +got):\n%s", diff)
	}
}
