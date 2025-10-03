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

package mysqlmylogin_test

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/veles/secrets/mysqlmylogin"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantRequired bool
	}{
		{
			name:         "valid .mylogin.cnf",
			path:         "/foo/.mylogin.cnf",
			wantRequired: true,
		},
		{
			name:         "valid .mylogin.cnf",
			path:         ".mylogin.cnf",
			wantRequired: true,
		},
		{
			name:         "invalid .mylogin.cnf",
			path:         "/foo.mylogin.cnf",
			wantRequired: false,
		},
		{
			name:         "invalid .mylogin.cnf",
			path:         "/foo.mylogin.cnf.ext",
			wantRequired: false,
		},
		{
			name:         "invalid .mylogin.cnf",
			path:         "/foo_mysqlmylogin_zoo.ext",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e filesystem.Extractor = mysqlmylogin.Extractor{}
			if got := e.FileRequired(simplefileapi.New(tt.path, nil)); got != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.wantRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		wantSecrets []*inventory.Secret
		wantError   error
	}{
		{
			name: "valid .mylogin.cnf file",
			path: "testdata/valid",
			wantSecrets: []*inventory.Secret{
				{
					Secret: mysqlmylogin.MysqlMyloginSection{
						SectionName: "local",
						User:        "root",
						Password:    "google",
						Host:        "localhost",
						Port:        "1234",
						Socket:      "socket"},
					Location: "testdata/valid",
				},
			},
		}, {
			name: "valid .mylogin.cnf file with multiple sections",
			path: "testdata/valid_multiple_sections",
			wantSecrets: []*inventory.Secret{
				{
					Secret: mysqlmylogin.MysqlMyloginSection{
						SectionName: "local",
						User:        "root",
						Password:    "google",
						Host:        "localhost",
						Port:        "1234",
						Socket:      "socket"},
					Location: "testdata/valid_multiple_sections",
				}, {
					Secret: mysqlmylogin.MysqlMyloginSection{
						SectionName: "client",
						User:        "admin",
						Password:    "password_client",
						Host:        "127.0.0.1",
						Port:        "4321",
						Socket:      "s"},
					Location: "testdata/valid_multiple_sections",
				},
			},
		},
		{
			name:        "invalid .mylogin.cnf file",
			path:        "testdata/invalid",
			wantError:   cmpopts.AnyError,
			wantSecrets: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := mysqlmylogin.New()
			d := t.TempDir()

			// Opening and Reading the Test File
			r, err := os.Open(tt.path)

			if err != nil {
				t.Fatal(err)
			}

			defer func() {
				if err = r.Close(); err != nil {
					t.Errorf("Close(): %v", err)
				}
			}()

			info, err := os.Stat(tt.path)
			if err != nil {
				t.Fatal(err)
			}

			input := &filesystem.ScanInput{
				FS: scalibrfs.DirFS(d), Path: tt.path, Reader: r, Root: d, Info: info,
			}

			got, err := e.Extract(t.Context(), input)

			wantInv := inventory.Inventory{Secrets: tt.wantSecrets}
			if diff := cmp.Diff(wantInv, got); diff != "" {
				t.Errorf("Secret mismatch (-want +got):\n%s", diff)
			}
			if !cmp.Equal(err, tt.wantError, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.path, err, tt.wantError)
			}
		})
	}
}
