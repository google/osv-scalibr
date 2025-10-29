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

package npmsource_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/misc/npmsource"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson/metadata"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestAnnotate_AbsolutePackagePath(t *testing.T) {
	copier := cpy.New(
		cpy.Func(proto.Clone),
		cpy.IgnoreAllUnexported(),
	)

	lockfiles := map[string]string{
		"testproject/package-lock.json": "testdata/package-lock.v1.json",
	}

	root := setupNPMLockfiles(t, lockfiles)

	inputPackage := &extractor.Package{
		Name:     "wrappy",
		PURLType: "npm",
		// Locations is the absolute path of the package.json file.
		Locations: []string{filepath.Join(root, "testproject/node_modules/dependency-1/package.json")},
	}
	inv := &inventory.Inventory{Packages: []*extractor.Package{copier.Copy(inputPackage).(*extractor.Package)}}

	input := &annotator.ScanInput{
		ScanRoot: scalibrfs.RealFSScanRoot(root),
	}

	wantPackage := &extractor.Package{
		Name:      "wrappy",
		PURLType:  "npm",
		Locations: []string{filepath.Join(root, "testproject/node_modules/dependency-1/package.json")},
		Metadata: &metadata.JavascriptPackageJSONMetadata{
			// We want to assert that the package was resolved from the NPM repository which means that
			// the lockfile was read from the relative path in the scan root.
			Source: metadata.PublicRegistry,
		},
	}

	err := npmsource.New().Annotate(t.Context(), input, inv)
	if err != nil {
		t.Errorf("Annotate(%v) error: %v; want error presence = false", inputPackage, err)
	}

	want := &inventory.Inventory{Packages: []*extractor.Package{wantPackage}}
	if diff := cmp.Diff(want, inv, protocmp.Transform()); diff != "" {
		t.Errorf("Annotate(%v): unexpected diff (-want +got):\n%s", inputPackage, diff)
	}
}

func TestAnnotate_LockfileV1(t *testing.T) {
	copier := cpy.New(
		cpy.Func(proto.Clone),
		cpy.IgnoreAllUnexported(),
	)

	testCases := []struct {
		name         string
		lockfiles    map[string]string
		inputPackage *extractor.Package
		wantPackage  *extractor.Package
		wantAnyErr   bool
	}{
		{
			name: "unfound dependency in lockfile",
			lockfiles: map[string]string{
				"testproject/package-lock.json": "testdata/package-lock.v1.json",
			},
			inputPackage: &extractor.Package{
				Name:      "abandoned-package",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/abandoned-package/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "abandoned-package",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/abandoned-package/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.Unknown,
				},
			},
		},
		{
			name: "dependency from private registry",
			lockfiles: map[string]string{
				"testproject/package-lock.json": "testdata/package-lock.v1.json",
			},
			inputPackage: &extractor.Package{
				Name:      "supports-color",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/supports-color/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "supports-color",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/supports-color/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.Other,
				},
			},
		},
		{
			name: "custom package from github (private registry)",
			lockfiles: map[string]string{
				"testproject/package-lock.json": "testdata/package-lock.v1.json",
			},
			inputPackage: &extractor.Package{
				Name:      "custom-package",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/custom-package/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "custom-package",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/custom-package/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.Other,
				},
			},
		},
		{
			name: "local package",
			lockfiles: map[string]string{
				"testproject/package-lock.json": "testdata/package-lock.v1.json",
			},
			inputPackage: &extractor.Package{
				Name:      "local-package",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/local-package/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "local-package",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/local-package/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.Local,
				},
			},
		},
		{
			name: "nested dependency",
			lockfiles: map[string]string{
				"testproject/package-lock.json": "testdata/package-lock.v1.json",
			},
			inputPackage: &extractor.Package{
				Name:      "wrappy",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/dependency-1/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "wrappy",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/dependency-1/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.PublicRegistry,
				},
			},
		},
		{
			name: "alias package",
			lockfiles: map[string]string{
				"testproject/package-lock.json": "testdata/package-lock.v1.json",
			},
			inputPackage: &extractor.Package{
				Name:      "string-width",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/dependency-1/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "string-width",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/dependency-1/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.PublicRegistry,
				},
			},
		},
		{
			name: "duplicated dependency",
			lockfiles: map[string]string{
				"testproject/package-lock.json": "testdata/package-lock.v1.json",
			},
			inputPackage: &extractor.Package{
				Name:      "@babel/highlight",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/dependency-1/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "@babel/highlight",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/dependency-1/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.PublicRegistry,
				},
			},
		},
		{
			name: "same package different group",
			lockfiles: map[string]string{
				"testproject/package-lock.json": "testdata/package-lock.v1.json",
			},
			inputPackage: &extractor.Package{
				Name:      "ajv",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/dependency-1/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "ajv",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/dependency-1/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.PublicRegistry,
				},
			},
		},
		{
			name:      "no lockfile present",
			lockfiles: map[string]string{},
			inputPackage: &extractor.Package{
				Name:      "abandoned-package",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/abandoned-package/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "abandoned-package",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/abandoned-package/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.Unknown,
				},
			},
			wantAnyErr: false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			packages := []*extractor.Package{copier.Copy(tt.inputPackage).(*extractor.Package)}
			inv := &inventory.Inventory{Packages: packages}

			root := setupNPMLockfiles(t, tt.lockfiles)
			input := &annotator.ScanInput{
				ScanRoot: scalibrfs.RealFSScanRoot(root),
			}

			err := npmsource.New().Annotate(t.Context(), input, inv)
			gotErr := err != nil
			if gotErr != tt.wantAnyErr {
				t.Errorf("Annotate_LockfileV1(%v) error: %v; want error presence = %v", tt.inputPackage, err, tt.wantAnyErr)
			}

			want := &inventory.Inventory{Packages: []*extractor.Package{tt.wantPackage}}
			if diff := cmp.Diff(want, inv, protocmp.Transform()); diff != "" {
				t.Errorf("Annotate_LockfileV1(%v): unexpected diff (-want +got):\n%s", tt.inputPackage, diff)
			}
		})
	}
}

func TestAnnotate_LockfileV2(t *testing.T) {
	copier := cpy.New(
		cpy.Func(proto.Clone),
		cpy.IgnoreAllUnexported(),
	)

	testCases := []struct {
		name         string
		lockfiles    map[string]string
		inputPackage *extractor.Package
		wantPackage  *extractor.Package
		wantAnyErr   bool
	}{
		{
			name: "unfound package in lockfile",
			lockfiles: map[string]string{
				"testproject/package-lock.json": "testdata/package-lock.json",
			},
			inputPackage: &extractor.Package{
				Name:      "abandoned-package",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/abandoned-package/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "abandoned-package",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/abandoned-package/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.Unknown,
				},
			},
		},
		{
			name: "dependency from private registry",
			lockfiles: map[string]string{
				"testproject/package-lock.json": "testdata/package-lock.json",
			},
			inputPackage: &extractor.Package{
				Name:      "supports-color",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/supports-color/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "supports-color",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/supports-color/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.Other,
				},
			},
		},
		{
			name: "local package",
			lockfiles: map[string]string{
				"testproject/package-lock.json": "testdata/package-lock.json",
			},
			inputPackage: &extractor.Package{
				Name:      "local-package",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/local-package/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "local-package",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/local-package/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.Local,
				},
			},
		},
		{
			name: "scoped packages from npm repository",
			lockfiles: map[string]string{
				"testproject/package-lock.json": "testdata/package-lock.json",
			},
			inputPackage: &extractor.Package{
				Name:      "@babel/code-frame",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/dependency-1/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "@babel/code-frame",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/dependency-1/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.PublicRegistry,
				},
			},
		},
		{
			name: "alias package",
			lockfiles: map[string]string{
				"testproject/package-lock.json": "testdata/package-lock.json",
			},
			inputPackage: &extractor.Package{
				Name:      "string-width",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/dependency-1/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "string-width",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/dependency-1/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.PublicRegistry,
				},
			},
		},
		{
			name: "custom package from github (private registry)",
			lockfiles: map[string]string{
				"testproject/package-lock.json": "testdata/package-lock.json",
			},
			inputPackage: &extractor.Package{
				Name:      "custom-package",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/custom-package/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "custom-package",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/custom-package/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.Other,
				},
			},
		},
		{
			name: "nested packages",
			lockfiles: map[string]string{
				"testproject/package-lock.json": "testdata/package-lock.json",
			},
			inputPackage: &extractor.Package{
				Name:      "wrappy",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/dependency-1/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "wrappy",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/dependency-1/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.PublicRegistry,
				},
			},
		},
		{
			name: "duplicated packages",
			lockfiles: map[string]string{
				"testproject/package-lock.json": "testdata/package-lock.json",
			},
			inputPackage: &extractor.Package{
				Name:      "@babel/highlight",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/dependency-1/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "@babel/highlight",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/dependency-1/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.PublicRegistry,
				},
			},
		},
		{
			name: "same package different group",
			lockfiles: map[string]string{
				"testproject/package-lock.json": "testdata/package-lock.json",
			},
			inputPackage: &extractor.Package{
				Name:      "ajv",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/dependency-1/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "ajv",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/dependency-1/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.PublicRegistry,
				},
			},
		},
		{
			name:      "no lockfile present",
			lockfiles: map[string]string{},
			inputPackage: &extractor.Package{
				Name:      "abandoned-package",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/abandoned-package/package.json"},
			},
			wantPackage: &extractor.Package{
				Name:      "abandoned-package",
				PURLType:  "npm",
				Locations: []string{"testproject/node_modules/abandoned-package/package.json"},
				Metadata: &metadata.JavascriptPackageJSONMetadata{
					Source: metadata.Unknown,
				},
			},
			wantAnyErr: false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			packages := []*extractor.Package{copier.Copy(tt.inputPackage).(*extractor.Package)}
			inv := &inventory.Inventory{Packages: packages}

			root := setupNPMLockfiles(t, tt.lockfiles)
			input := &annotator.ScanInput{
				ScanRoot: scalibrfs.RealFSScanRoot(root),
			}

			err := npmsource.New().Annotate(t.Context(), input, inv)
			gotErr := err != nil
			if gotErr != tt.wantAnyErr {
				t.Errorf("Annotate_LockfileV1(%v) error: %v; want error presence = %v", tt.inputPackage, err, tt.wantAnyErr)
			}

			want := &inventory.Inventory{Packages: []*extractor.Package{tt.wantPackage}}
			if diff := cmp.Diff(want, inv, protocmp.Transform()); diff != "" {
				t.Errorf("Annotate_LockfileV2(%v): unexpected diff (-want +got):\n%s", tt.inputPackage, diff)
			}
		})
	}
}

func TestMapNPMProjectRootsToPackages(t *testing.T) {
	testCases := []struct {
		name          string
		inputPackages []*extractor.Package
		want          map[string][]*extractor.Package
	}{
		{
			name: "maps root directory to package from node_modules/../package.json",
			inputPackages: []*extractor.Package{
				{
					Name:      "acorn",
					Version:   "1.0.0",
					PURLType:  "npm",
					Locations: []string{"testproject/node_modules/dependency-1/package.json"},
				},
			},
			want: map[string][]*extractor.Package{
				"testproject": []*extractor.Package{
					{
						Name:      "acorn",
						Version:   "1.0.0",
						PURLType:  "npm",
						Locations: []string{"testproject/node_modules/dependency-1/package.json"},
					},
				},
			},
		},
		{
			name: "maps root directory to package from node_modules/../package.json",
			inputPackages: []*extractor.Package{
				{
					Name:      "acorn",
					Version:   "1.0.0",
					PURLType:  "npm",
					Locations: []string{"testproject/node_modules/dependency-1/package.json"},
				},
			},
			want: map[string][]*extractor.Package{
				"testproject": []*extractor.Package{
					{
						Name:      "acorn",
						Version:   "1.0.0",
						PURLType:  "npm",
						Locations: []string{"testproject/node_modules/dependency-1/package.json"},
					},
				},
			},
		},
		{
			name: "no map for non-npm packages",
			inputPackages: []*extractor.Package{
				{
					Name:      "acorn",
					Version:   "1.0.0",
					PURLType:  "pypi",
					Locations: []string{"testproject/node_modules/dependency-1/package.json"},
				},
			},
			want: make(map[string][]*extractor.Package),
		},
		{
			name: "no map for non-package.json",
			inputPackages: []*extractor.Package{
				{
					Name:      "acorn",
					Version:   "1.0.0",
					PURLType:  "npm",
					Locations: []string{"testproject/node_modules/dependency-2/package2.json"},
				},
			},
			want: make(map[string][]*extractor.Package),
		},
		{
			name: "no map for non-node_modules directory",
			inputPackages: []*extractor.Package{
				{
					Name:      "acorn",
					Version:   "1.0.0",
					PURLType:  "npm",
					Locations: []string{"testproject/package.json"},
				},
			},
			want: make(map[string][]*extractor.Package),
		},
		{
			name: "no map for empty locations",
			inputPackages: []*extractor.Package{
				{
					Name:      "acorn",
					Version:   "1.0.0",
					PURLType:  "npm",
					Locations: []string{""},
				},
			},
			want: make(map[string][]*extractor.Package),
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got := npmsource.MapNPMProjectRootsToPackages(tt.inputPackages)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("MapNPMProjectRootsToPackages(%v): unexpected diff (-want +got): %v", tt.inputPackages, diff)
			}
		})
	}
}

func TestResolvedFromLockfile(t *testing.T) {
	testCases := []struct {
		name        string
		lockfiles   map[string]string
		wantDeps    map[string]metadata.NPMPackageSource
		wantAnyErr  bool
		skipWindows bool
	}{
		// All 3 lockfiles have the same file structure.
		{
			name: "parse package-lock.json",
			lockfiles: map[string]string{
				"testproject/package-lock.json": "testdata/package-lock.json",
			},
			wantDeps: map[string]metadata.NPMPackageSource{
				"acorn":             metadata.PublicRegistry,
				"wrappy":            metadata.PublicRegistry,
				"custom-package":    metadata.Other,
				"supports-color":    metadata.Other,
				"ajv":               metadata.PublicRegistry,
				"@babel/highlight":  metadata.PublicRegistry,
				"@babel/code-frame": metadata.PublicRegistry,
				"string-width":      metadata.PublicRegistry,
				"@parcel/watcher":   metadata.Unknown,
				"local-package":     metadata.Local,
			},
			skipWindows: true,
		},
		{
			name: "parse npm-shrinkwrap.json",
			lockfiles: map[string]string{
				"testproject/npm-shrinkwrap.json": "testdata/package-lock.json",
			},
			wantDeps: map[string]metadata.NPMPackageSource{
				"acorn":             metadata.PublicRegistry,
				"wrappy":            metadata.PublicRegistry,
				"custom-package":    metadata.Other,
				"supports-color":    metadata.Other,
				"ajv":               metadata.PublicRegistry,
				"@babel/highlight":  metadata.PublicRegistry,
				"@babel/code-frame": metadata.PublicRegistry,
				"string-width":      metadata.PublicRegistry,
				"@parcel/watcher":   metadata.Unknown,
				"local-package":     metadata.Local,
			},
			skipWindows: true,
		},
		{
			name: "parse hidden package-lock.json in /node_modules",
			lockfiles: map[string]string{
				"testproject/node_modules/.package-lock.json": "testdata/package-lock.json",
			},
			wantDeps: map[string]metadata.NPMPackageSource{
				"acorn":             metadata.PublicRegistry,
				"wrappy":            metadata.PublicRegistry,
				"custom-package":    metadata.Other,
				"supports-color":    metadata.Other,
				"ajv":               metadata.PublicRegistry,
				"@babel/highlight":  metadata.PublicRegistry,
				"@babel/code-frame": metadata.PublicRegistry,
				"string-width":      metadata.PublicRegistry,
				"@parcel/watcher":   metadata.Unknown,
				"local-package":     metadata.Local,
			},
			skipWindows: true,
		},
		{
			name:        "parse with no lockfiles returns nothing",
			lockfiles:   map[string]string{},
			wantDeps:    nil,
			wantAnyErr:  false,
			skipWindows: false,
		},
		{
			name: "parse empty lockfiles returns error",
			lockfiles: map[string]string{
				"testproject/node_modules/.package-lock.json": "empty-file.json",
			},
			wantDeps:    nil,
			wantAnyErr:  true,
			skipWindows: true,
		},
		{
			name: "parse lockfiles without dependencies and packages returns nothing",
			lockfiles: map[string]string{
				"testproject/node_modules/.package-lock.json": "testdata/no-dep-list-package-lock.json",
			},
			wantDeps:    map[string]metadata.NPMPackageSource{},
			wantAnyErr:  false,
			skipWindows: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			root := setupNPMLockfiles(t, tt.lockfiles)
			fsys := scalibrfs.DirFS(root)

			got, err := npmsource.ResolvedFromLockfile("testproject", fsys)
			gotErr := err != nil
			if gotErr != tt.wantAnyErr {
				t.Errorf("ResolvedFromLockfile(testproject) error: %v; want error presence = %v", err, tt.wantAnyErr)
			}
			if diff := cmp.Diff(tt.wantDeps, got); diff != "" {
				t.Errorf("ResolvedFromLockfile(testproject): unexpected diff (-want +got): %v", diff)
			}
		})
	}
}

func setupNPMLockfiles(t *testing.T, dbPaths map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for dbPath, contentFile := range dbPaths {
		dbDir := filepath.Join(root, filepath.Dir(dbPath))
		if err := os.MkdirAll(dbDir, 0777); err != nil {
			t.Fatalf("Error creating directory %q: %v", dbDir, err)
		}

		if contentFile != "empty-file.json" {
			content, err := os.ReadFile(contentFile)
			if err != nil {
				t.Fatalf("Error reading content file %q: %v", contentFile, err)
			}
			writeFile(t, filepath.Join(root, dbPath), content)
		} else {
			writeFile(t, filepath.Join(root, dbPath), []byte{})
		}
	}
	return root
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("Error creating file %q: %v", path, err)
	}
}
