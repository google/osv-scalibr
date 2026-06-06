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

package condaenv_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/condaenv"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestNew(t *testing.T) {
	e, err := condaenv.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("condaenv.New(): %v", err)
	}
	if e == nil {
		t.Fatal("condaenv.New() returned nil")
	}
}

func TestName(t *testing.T) {
	e, _ := condaenv.New(&cpb.PluginConfig{})
	if got, want := e.Name(), condaenv.Name; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestFileRequired(t *testing.T) {
	e, _ := condaenv.New(&cpb.PluginConfig{})

	tests := []struct {
		name     string
		path     string
		wantBool bool
	}{
		{
			name:     "environment.yml at root",
			path:     "environment.yml",
			wantBool: true,
		},
		{
			name:     "environment.yaml alternative extension",
			path:     "environment.yaml",
			wantBool: true,
		},
		{
			name:     "nested environment.yml",
			path:     "project/conda/environment.yml",
			wantBool: true,
		},
		{
			name:     "requirements.txt is not a conda env file",
			path:     "requirements.txt",
			wantBool: false,
		},
		{
			name:     "prefix match should not match",
			path:     "my-environment.yml",
			wantBool: false,
		},
		{
			name:     "conda-lock.yml is a different format",
			path:     "conda-lock.yml",
			wantBool: false,
		},
		{
			name:     "Pipfile is not environment.yml",
			path:     "Pipfile",
			wantBool: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{FileName: "environment.yml", FileSize: 512}))
			if got != tt.wantBool {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.wantBool)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	e, _ := condaenv.New(&cpb.PluginConfig{})

	tests := []extracttest.TestTableEntry{
		{
			Name: "pinned conda packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/pinned.yml",
			},
			WantPackages: []*extractor.Package{
				{Name: "python", Version: "3.11", PURLType: purl.TypeConda, Location: extractor.LocationFromPath("testdata/pinned.yml")},
				{Name: "numpy", Version: "1.26.0", PURLType: purl.TypeConda, Location: extractor.LocationFromPath("testdata/pinned.yml")},
				{Name: "scipy", Version: "1.11.4", PURLType: purl.TypeConda, Location: extractor.LocationFromPath("testdata/pinned.yml")},
				{Name: "matplotlib", Version: "3.8.0", PURLType: purl.TypeConda, Location: extractor.LocationFromPath("testdata/pinned.yml")},
			},
		},
		{
			Name: "pip section is ignored",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-pip.yml",
			},
			WantPackages: []*extractor.Package{
				{Name: "python", Version: "3.10", PURLType: purl.TypeConda, Location: extractor.LocationFromPath("testdata/with-pip.yml")},
				{Name: "torch", Version: "2.1.0", PURLType: purl.TypeConda, Location: extractor.LocationFromPath("testdata/with-pip.yml")},
			},
		},
		{
			Name: "empty dependencies produces no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.yml",
			},
			WantPackages: nil,
		},
		{
			Name: "invalid yaml returns error",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.yml",
			},
			WantPackages: nil,
			WantErr:      extracttest.ContainsErrStr{Str: "yaml"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := e.Extract(context.Background(), &scanInput)

			if tt.WantErr != nil {
				if err == nil {
					t.Fatalf("Extract() error = nil, want %v", tt.WantErr)
				}
				var wantContains extracttest.ContainsErrStr
				if errors.As(tt.WantErr, &wantContains) {
					if !strings.Contains(err.Error(), wantContains.Str) {
						t.Fatalf("Extract() error = %q, want to contain %q", err.Error(), wantContains.Str)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("Extract() error = %v, want nil", err)
			}

			opts := cmp.Options{
				cmpopts.IgnoreUnexported(extractor.Package{}),
				cmpopts.EquateEmpty(),
				cmpopts.SortSlices(extracttest.PackageCmpLess),
			}
			if diff := cmp.Diff(tt.WantPackages, got.Packages, opts); diff != "" {
				t.Errorf("Extract() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExtract_PURLType(t *testing.T) {
	e, _ := condaenv.New(&cpb.PluginConfig{})

	scanInput := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
		Path: "testdata/pinned.yml",
	})
	defer extracttest.CloseTestScanInput(t, scanInput)

	got, err := e.Extract(context.Background(), &scanInput)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if len(got.Packages) == 0 {
		t.Fatal("got 0 packages, want > 0")
	}

	for _, pkg := range got.Packages {
		if pkg.PURLType != purl.TypeConda {
			t.Errorf("Package %q PURLType = %q, want %q", pkg.Name, pkg.PURLType, purl.TypeConda)
		}
		p := pkg.PURL()
		if p.Type != purl.TypeConda {
			t.Errorf("Package %q PURL().Type = %q, want %q", pkg.Name, p.Type, purl.TypeConda)
		}
	}
}
