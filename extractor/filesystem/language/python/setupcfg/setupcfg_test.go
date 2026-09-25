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

package setupcfg_test

import (
	"context"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/setupcfg"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "setup.cfg", path: "setup.cfg", want: true},
		{name: "nested setup.cfg", path: "project/setup.cfg", want: true},
		{name: "not setup.cfg", path: "setup.py", want: false},
		{name: "not setup.cfg 2", path: "mysetup.cfg", want: false},
		{name: "requirements.txt", path: "requirements.txt", want: false},
	}
	e := setupcfg.Extractor{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := e.FileRequired(simplefileapi.New(tc.path, nil))
			if got != tc.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantPkgs []*extractor.Package
		wantErr  bool
	}{
		{
			name:     "empty — no deps sections",
			path:     "testdata/empty.cfg",
			wantPkgs: nil,
		},
		{
			name: "valid — installs and extras",
			path: "testdata/valid.cfg",
			wantPkgs: []*extractor.Package{
				{
					Name:     "requests",
					Version:  "2.31.0",
					PURLType: purl.TypePyPi,
					Metadata: &setupcfg.Metadata{
						Requirement:       "requests==2.31.0",
						VersionComparator: "==",
					},
				},
				{
					Name:     "flask",
					Version:  "2.0",
					PURLType: purl.TypePyPi,
					Metadata: &setupcfg.Metadata{
						Requirement:       "flask>=2.0",
						VersionComparator: ">=",
					},
				},
				{
					Name:     "click",
					Version:  "",
					PURLType: purl.TypePyPi,
					Metadata: &setupcfg.Metadata{
						Requirement: "Click",
					},
				},
				{
					Name:     "numpy",
					Version:  "1.24.0",
					PURLType: purl.TypePyPi,
					Metadata: &setupcfg.Metadata{
						Requirement:       "numpy~=1.24.0",
						VersionComparator: "~=",
					},
				},
				// cryptography>=41.0,<42.0 — compound, version stripped but pkg kept.
				// Requirement preserves the full original string.
				{
					Name:     "cryptography",
					Version:  "",
					PURLType: purl.TypePyPi,
					Metadata: &setupcfg.Metadata{
						Requirement: "cryptography>=41.0,<42.0",
					},
				},
				// importlib-metadata with env marker — included.
				// Requirement preserves the full original string with marker.
				{
					Name:     "importlib-metadata",
					Version:  "",
					PURLType: purl.TypePyPi,
					Metadata: &setupcfg.Metadata{
						Requirement: "importlib-metadata; python_version < \"3.10\"",
					},
				},
				// Pillow[jpeg]==10.0.0 — extras preserved in Requirement, name normalized.
				{
					Name:     "pillow",
					Version:  "10.0.0",
					PURLType: purl.TypePyPi,
					Metadata: &setupcfg.Metadata{
						Requirement:       "Pillow[jpeg]==10.0.0",
						VersionComparator: "==",
					},
				},
				// file: dep is skipped entirely.
				// dev extras.
				{
					Name:     "pytest",
					Version:  "7.0",
					PURLType: purl.TypePyPi,
					Metadata: &setupcfg.Metadata{
						Requirement:       "pytest>=7.0",
						VersionComparator: ">=",
						DepGroupVals:      []string{"dev"},
					},
				},
				{
					Name:     "pytest-cov",
					Version:  "",
					PURLType: purl.TypePyPi,
					Metadata: &setupcfg.Metadata{
						Requirement:  "pytest-cov",
						DepGroupVals: []string{"dev"},
					},
				},
				// tox in test extras.
				{
					Name:     "tox",
					Version:  "",
					PURLType: purl.TypePyPi,
					Metadata: &setupcfg.Metadata{
						Requirement:  "tox",
						DepGroupVals: []string{"test"},
					},
				},
				// coverage!=5.0 — unsupported constraint, version stripped but kept.
				// Requirement preserves the full original string.
				{
					Name:     "coverage",
					Version:  "",
					PURLType: purl.TypePyPi,
					Metadata: &setupcfg.Metadata{
						Requirement:  "coverage!=5.0",
						DepGroupVals: []string{"test"},
					},
				},
			},
		},
		{
			name: "comments between continuation lines",
			path: "testdata/comments_between.cfg",
			wantPkgs: []*extractor.Package{
				{
					Name:     "requests",
					Version:  "2.31.0",
					PURLType: purl.TypePyPi,
					Metadata: &setupcfg.Metadata{
						Requirement:       "requests==2.31.0",
						VersionComparator: "==",
					},
				},
				{
					Name:     "urllib3",
					Version:  "1.26.0",
					PURLType: purl.TypePyPi,
					Metadata: &setupcfg.Metadata{
						Requirement:       "urllib3>=1.26.0",
						VersionComparator: ">=",
					},
				},
			},
		},
		{
			name: "duplicate dep across extras merges groups",
			path: "testdata/duplicate_extras.cfg",
			wantPkgs: []*extractor.Package{
				{
					Name:     "pytest",
					Version:  "7.0",
					PURLType: purl.TypePyPi,
					Metadata: &setupcfg.Metadata{
						Requirement:       "pytest>=7.0",
						VersionComparator: ">=",
						DepGroupVals:      []string{"dev", "test"},
					},
				},
				{
					Name:     "coverage",
					Version:  "",
					PURLType: purl.TypePyPi,
					Metadata: &setupcfg.Metadata{
						Requirement:  "coverage",
						DepGroupVals: []string{"test"},
					},
				},
			},
		},
	}

	e := setupcfg.Extractor{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Open(tc.path)
			if err != nil {
				t.Fatalf("os.Open(%q): %v", tc.path, err)
			}
			defer f.Close()

			info, err := f.Stat()
			if err != nil {
				t.Fatalf("f.Stat(): %v", err)
			}

			got, err := e.Extract(context.Background(), &filesystem.ScanInput{
				Path:   tc.path,
				Reader: f,
				Info:   info,
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("Extract() error = %v, wantErr %v", err, tc.wantErr)
			}

			want := inventory.Inventory{Packages: tc.wantPkgs}
			if diff := cmp.Diff(want, got,
				cmpopts.IgnoreFields(extractor.Package{}, "Location"),
				cmpopts.EquateEmpty(),
			); diff != "" {
				t.Errorf("Extract() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
