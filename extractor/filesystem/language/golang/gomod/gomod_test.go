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

package gomod_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			inputPath: "",
			want:      false,
		},
		{
			inputPath: "go.mod",
			want:      true,
		},
		{
			inputPath: "path/to/my/go.mod",
			want:      true,
		},
		{
			inputPath: "path/to/my/go.mod/file",
			want:      false,
		},
		{
			inputPath: "path/to/my/go.mod.file",
			want:      false,
		},
		{
			inputPath: "path.to.my.go.mod",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			e := gomod.Extractor{}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []*extracttest.TestTableEntry{
		{
			Name: "invalid",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-go-mod.mod",
			},
			WantErr: extracttest.ContainsErrStr{Str: "could not extract from"},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.mod",
			},
			WantPackages: nil,
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.mod",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/one-package.mod"},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.mod",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/two-packages.mod"},
				},
				{
					Name:      "gopkg.in/yaml.v2",
					Version:   "2.4.0",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/two-packages.mod"},
				},
				{
					Name:      "stdlib",
					Version:   "1.17",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/two-packages.mod"},
				},
			},
		},
		{
			Name: "toolchain",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/toolchain.mod",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/toolchain.mod"},
				},
				{
					Name:      "stdlib",
					Version:   "1.23.6",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/toolchain.mod"},
				},
			},
		},
		{
			Name: "toolchain with suffix",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/toolchain-with-suffix.mod",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/toolchain-with-suffix.mod"},
				},
				{
					Name:      "stdlib",
					Version:   "1.23.6",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/toolchain-with-suffix.mod"},
				},
			},
		},
		{
			Name: "indirect packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/indirect-packages.mod",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/indirect-packages.mod"},
				},
				{
					Name:      "gopkg.in/yaml.v2",
					Version:   "2.4.0",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/indirect-packages.mod"},
				},
				{
					Name:      "github.com/mattn/go-colorable",
					Version:   "0.1.9",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/indirect-packages.mod"},
				},
				{
					Name:      "github.com/mattn/go-isatty",
					Version:   "0.0.14",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/indirect-packages.mod"},
				},
				{
					Name:      "golang.org/x/sys",
					Version:   "0.0.0-20210630005230-0f9fa26af87c",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/indirect-packages.mod"},
				},
				{
					Name:      "stdlib",
					Version:   "1.17",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/indirect-packages.mod"},
				},
			},
		},
		{
			Name: "replacements_ one",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/replace-one.mod",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "example.com/fork/net",
					Version:   "1.4.5",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/replace-one.mod"},
				},
			},
		},
		{
			Name: "replacements_ mixed",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/replace-mixed.mod",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "example.com/fork/net",
					Version:   "1.4.5",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/replace-mixed.mod"},
				},
				{
					Name:      "golang.org/x/net",
					Version:   "0.5.6",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/replace-mixed.mod"},
				},
			},
		},
		{
			Name: "replacements_ local",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/replace-local.mod",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "./fork/net",
					Version:   "",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/replace-local.mod"},
				},
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/replace-local.mod"},
				},
			},
		},
		{
			Name: "replacements_ different",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/replace-different.mod",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "example.com/fork/foe",
					Version:   "1.4.5",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/replace-different.mod"},
				},
				{
					Name:      "example.com/fork/foe",
					Version:   "1.4.2",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/replace-different.mod"},
				},
			},
		},
		{
			Name: "replacements_ not required",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/replace-not-required.mod",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "golang.org/x/net",
					Version:   "0.5.6",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/replace-not-required.mod"},
				},
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/replace-not-required.mod"},
				},
			},
		},
		{
			Name: "replacements_ no version",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/replace-no-version.mod",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "example.com/fork/net",
					Version:   "1.4.5",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/replace-no-version.mod"},
				},
			},
		},
		{
			Name: "test extractor for go > 1.16",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/indirect-1.23.mod",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "github.com/sirupsen/logrus",
					Version:   "1.9.3",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/indirect-1.23.mod"},
				},
				{
					Name:      "golang.org/x/sys",
					Version:   "0.0.0-20220715151400-c0bba94af5f8",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/indirect-1.23.mod"},
				},
				{
					Name:      "stdlib",
					Version:   "1.23",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/indirect-1.23.mod"},
				},
			},
		},
		{
			Name: "test extractor for go <=1.16",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/indirect-1.16.mod",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "github.com/davecgh/go-spew",
					Version:   "1.1.1",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/indirect-1.16.sum"},
				},
				{
					Name:      "github.com/pmezard/go-difflib",
					Version:   "1.0.0",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/indirect-1.16.sum"},
				},
				{
					Name:     "github.com/sirupsen/logrus",
					Version:  "1.9.3",
					PURLType: purl.TypeGolang,
					Locations: []string{
						"testdata/indirect-1.16.mod", "testdata/indirect-1.16.sum",
					},
				},
				{
					Name:      "github.com/stretchr/testify",
					Version:   "1.7.0",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/indirect-1.16.sum"},
				},
				{
					Name:      "golang.org/x/sys",
					Version:   "0.0.0-20220715151400-c0bba94af5f8",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/indirect-1.16.sum"},
				},
				{
					Name:      "gopkg.in/yaml.v3",
					Version:   "3.0.0-20200313102051-9f266ea9e77c",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/indirect-1.16.sum"},
				},
				{
					Name:      "stdlib",
					Version:   "1.16",
					PURLType:  purl.TypeGolang,
					Locations: []string{"testdata/indirect-1.16.mod"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := gomod.New()

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(context.Background(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
