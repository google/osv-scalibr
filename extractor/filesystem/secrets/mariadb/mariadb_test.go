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

package mariadb_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/mariadb"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{inputPath: "", want: false},

		// linux
		{inputPath: `my.cnf`, want: true},
		{inputPath: `/Users/example/.my.cnf`, want: true},

		//windows
		{inputPath: `System Windows Directory\my.cnf`, want: true},
		{inputPath: `c:\my.ini`, want: true},
		{inputPath: `installdir\data\my.cnf`, want: true},
		{inputPath: `installdir\data\my.ini`, want: true},

		// wrong paths
		{inputPath: `/etc/ssl/openssl.cnf`, want: false},
		{inputPath: `go.mod`, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			e := mariadb.Extractor{}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	type entry struct {
		Name          string
		FollowInclude bool
		Path          string
		WantSecrets   []*inventory.Secret
		WantErr       error
	}

	tests := []*entry{
		{
			Name: "empty",
			Path: "empty.cnf",
		},
		{
			Name:          "real.cnf",
			FollowInclude: false,
			Path:          "real.cnf",
		},
		{
			Name:          "real.ini",
			FollowInclude: false,
			Path:          "real.ini",
		},
		{
			Name:          "secret",
			FollowInclude: false,
			Path:          "secret.cnf",
			WantSecrets: []*inventory.Secret{
				{
					Secret:   mariadb.Credentials{Section: "mariadb-client", User: "root", Password: "secret_password"},
					Location: "secret.cnf",
				},
			},
		},
		{
			Name:          "include_file",
			FollowInclude: true,
			Path:          "include_file.cnf",
			WantSecrets: []*inventory.Secret{
				{
					Secret:   mariadb.Credentials{Section: "mariadb-client", User: "root", Password: "secret_password"},
					Location: "secret.cnf",
				},
			},
		},
		{
			Name:          "include_dir",
			FollowInclude: true,
			Path:          "include_dir.cnf",
		},
		{
			Name:          "bad_include",
			FollowInclude: true,
			Path:          "bad_include.cnf",
			WantErr:       extracttest.ContainsErrStr{Str: "could not open"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := mariadb.New(mariadb.Config{
				FollowInclude: tt.FollowInclude,
			})

			inputCfg := extracttest.ScanInputMockConfig{
				Path:         tt.Path,
				FakeScanRoot: "testdata",
			}

			scanInput := extracttest.GenerateScanInputMock(t, inputCfg)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Secrets: tt.WantSecrets}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.Path, diff)
			}
		})
	}
}
