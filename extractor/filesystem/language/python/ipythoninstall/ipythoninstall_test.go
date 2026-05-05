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

package ipythoninstall_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/ipythoninstall"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "nb.ipynb", want: true},
		{path: "nb.ipy", want: true},
		{path: "nb.py", want: false},
		{path: "README.md", want: false},
	}

	e, err := ipythoninstall.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("ipythoninstall.New() error: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{FileSize: 1}))
			if got != tt.want {
				t.Errorf("FileRequired(%q)=%v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "ipynb inline installs",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/inline.ipynb",
			},
			WantPackages: []*extractor.Package{
				{Name: "pandas", Version: "2.2.2", PURLType: purl.TypePyPi, Location: extractor.LocationFromPath("testdata/inline.ipynb")},
				{Name: "numpy", Version: "", PURLType: purl.TypePyPi, Location: extractor.LocationFromPath("testdata/inline.ipynb")},
				{Name: "scikit-learn", Version: "1.5.0", PURLType: purl.TypeConda, Location: extractor.LocationFromPath("testdata/inline.ipynb")},
				{Name: "polars", Version: "0.20.31", PURLType: purl.TypeConda, Location: extractor.LocationFromPath("testdata/inline.ipynb")},
			},
		},
		{
			Name: "ipy inline installs",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/inline.ipy",
			},
			WantPackages: []*extractor.Package{
				{Name: "uvicorn", Version: "0.34.2", PURLType: purl.TypePyPi, Location: extractor.LocationFromPath("testdata/inline.ipy")},
			},
		},
		{
			Name: "documented install magics",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/install_magics.ipy",
			},
			WantPackages: []*extractor.Package{
				{Name: "pandas", Version: "2.2.2", PURLType: purl.TypePyPi, Location: extractor.LocationFromPath("testdata/install_magics.ipy")},
				{Name: "scipy", Version: "1.14.1", PURLType: purl.TypeConda, Location: extractor.LocationFromPath("testdata/install_magics.ipy")},
				{Name: "scikit-learn", Version: "1.5.0", PURLType: purl.TypeConda, Location: extractor.LocationFromPath("testdata/install_magics.ipy")},
				{Name: "polars", Version: "0.20.31", PURLType: purl.TypeConda, Location: extractor.LocationFromPath("testdata/install_magics.ipy")},
				{Name: "anyio", Version: "4.6.2.post1", PURLType: purl.TypePyPi, Location: extractor.LocationFromPath("testdata/install_magics.ipy")},
				{Name: "fastapi", Version: "0.115.0", PURLType: purl.TypePyPi, Location: extractor.LocationFromPath("testdata/install_magics.ipy")},
			},
		},
		{
			Name: "conda install URLs",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/conda_urls.ipy",
			},
			WantPackages: []*extractor.Package{
				{Name: "requests", Version: "2.32.3", PURLType: purl.TypeConda, Location: extractor.LocationFromPath("testdata/conda_urls.ipy")},
				{Name: "certifi", Version: "2025.4.26", PURLType: purl.TypeConda, Location: extractor.LocationFromPath("testdata/conda_urls.ipy")},
				{Name: "plainpkg", Version: "1.2.3", PURLType: purl.TypeConda, Location: extractor.LocationFromPath("testdata/conda_urls.ipy")},
				{Name: "jupyterlab", Version: "4.3.0", PURLType: purl.TypeConda, Location: extractor.LocationFromPath("testdata/conda_urls.ipy")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			e, err := ipythoninstall.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("ipythoninstall.New() error: %v", err)
			}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := e.Extract(t.Context(), &scanInput)
			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Extract() error diff (-want +got):\n%s", diff)
			}
			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("Extract() packages diff (-want +got):\n%s", diff)
			}
		})
	}
}
