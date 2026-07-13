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

package rpkg_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/r/rpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestNew(t *testing.T) {
	e, err := rpkg.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("rpkg.New(): %v", err)
	}
	if e == nil {
		t.Fatal("rpkg.New() returned nil")
	}
}

func TestName(t *testing.T) {
	e, _ := rpkg.New(&cpb.PluginConfig{})
	if got, want := e.Name(), rpkg.Name; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestFileRequired(t *testing.T) {
	e, _ := rpkg.New(&cpb.PluginConfig{})

	tests := []struct {
		name     string
		path     string
		wantBool bool
	}{
		{
			name:     "DESCRIPTION in R/library",
			path:     "usr/lib/R/library/ggplot2/DESCRIPTION",
			wantBool: true,
		},
		{
			name:     "DESCRIPTION in R/site-library",
			path:     "usr/local/lib/R/site-library/dplyr/DESCRIPTION",
			wantBool: true,
		},
		{
			name:     "DESCRIPTION in versioned x86_64 R lib",
			path:     "home/user/R/x86_64-pc-linux-gnu-library/4.3/tidyverse/DESCRIPTION",
			wantBool: true,
		},
		{
			name:     "DESCRIPTION in aarch64 R lib",
			path:     "home/user/R/aarch64-unknown-linux-gnu-library/4.2/Rcpp/DESCRIPTION",
			wantBool: true,
		},
		{
			name:     "DESCRIPTION in lib/R path",
			path:     "usr/lib64/R/library/lattice/DESCRIPTION",
			wantBool: true,
		},
		{
			name:     "wrong filename - NAMESPACE",
			path:     "usr/lib/R/library/ggplot2/NAMESPACE",
			wantBool: false,
		},
		{
			name:     "wrong filename - R file",
			path:     "usr/lib/R/library/ggplot2/ggplot2.R",
			wantBool: false,
		},
		{
			name:     "DESCRIPTION in non-R path",
			path:     "home/user/projects/myapp/DESCRIPTION",
			wantBool: false,
		},
		{
			name:     "DESCRIPTION at root",
			path:     "DESCRIPTION",
			wantBool: false,
		},
		{
			name:     "DESCRIPTION in doc path",
			path:     "usr/share/doc/libfoo/DESCRIPTION",
			wantBool: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{FileName: "DESCRIPTION", FileSize: 512}))
			if got != tt.wantBool {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.wantBool)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	e, _ := rpkg.New(&cpb.PluginConfig{})

	tests := []extracttest.TestTableEntry{
		{
			Name: "ggplot2 package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/ggplot2/DESCRIPTION",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "ggplot2",
					Version:  "3.4.4",
					PURLType: purl.TypeCran,
					Location: extractor.LocationFromPath("testdata/ggplot2/DESCRIPTION"),
				},
			},
		},
		{
			Name: "dplyr with continuation lines",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/dplyr/DESCRIPTION",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "dplyr",
					Version:  "1.1.4",
					PURLType: purl.TypeCran,
					Location: extractor.LocationFromPath("testdata/dplyr/DESCRIPTION"),
				},
			},
		},
		{
			Name: "invalid DESCRIPTION missing Package/Version",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid/DESCRIPTION",
			},
			WantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := e.Extract(context.Background(), &scanInput)
			if err != nil && tt.WantErr == nil {
				t.Fatalf("Extract() error = %v, wantErr = nil", err)
			}

			opts := cmp.Options{
				cmpopts.IgnoreUnexported(extractor.Package{}),
				cmpopts.EquateEmpty(),
			}
			if diff := cmp.Diff(tt.WantPackages, got.Packages, opts); diff != "" {
				t.Errorf("Extract() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExtract_PURLType(t *testing.T) {
	e, _ := rpkg.New(&cpb.PluginConfig{})

	scanInput := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
		Path: "testdata/ggplot2/DESCRIPTION",
	})
	defer extracttest.CloseTestScanInput(t, scanInput)

	got, err := e.Extract(context.Background(), &scanInput)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if len(got.Packages) != 1 {
		t.Fatalf("got %d packages, want 1", len(got.Packages))
	}

	pkg := got.Packages[0]
	if pkg.PURLType != purl.TypeCran {
		t.Errorf("PURLType = %q, want %q", pkg.PURLType, purl.TypeCran)
	}

	p := pkg.PURL()
	if p.Type != purl.TypeCran {
		t.Errorf("PURL().Type = %q, want %q", p.Type, purl.TypeCran)
	}
	if p.Name != "ggplot2" {
		t.Errorf("PURL().Name = %q, want %q", p.Name, "ggplot2")
	}
	if p.Version != "3.4.4" {
		t.Errorf("PURL().Version = %q, want %q", p.Version, "3.4.4")
	}
}
