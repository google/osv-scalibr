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

package pgpass_test

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/veles/secrets/pgpass"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantRequired bool
	}{
		{
			name:         "valid .pgpass",
			path:         "/foo/.pgpass",
			wantRequired: true,
		},
		{
			name:         "valid .pgpass",
			path:         ".pgpass",
			wantRequired: true,
		},
		{
			name:         "invalid .pgpass",
			path:         "/foo.pgpass",
			wantRequired: false,
		},
		{
			name:         "invalid .pgpass",
			path:         "/foo.pgpass.ext",
			wantRequired: false,
		},
		{
			name:         "invalid .pgpass",
			path:         "/foo_pgpass_zoo.ext",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e filesystem.Extractor = pgpass.Extractor{}
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
	}{
		{
			name: "valid .pgpass file",
			path: "testdata/valid",
			wantSecrets: []*inventory.Secret{
				{
					Secret: pgpass.Pgpass{Hostname: "localhost",
						Port:     "5432",
						Database: "mydb",
						Username: "myuser",
						Password: "mypassword"},
					Location: "testdata/valid",
				},
				{
					Secret: pgpass.Pgpass{Hostname: "hostname",
						Port:     "1234",
						Database: "testdb",
						Username: "testuser",
						Password: "testpass123"},
					Location: "testdata/valid",
				},
				{
					Secret: pgpass.Pgpass{Hostname: "hostname",
						Port:     "1234",
						Database: "testdb",
						Username: "testuser",
						Password: "passw*ord"},
					Location: "testdata/valid",
				},
				{
					Secret: pgpass.Pgpass{Hostname: "*",
						Port:     "*",
						Database: "db",
						Username: "admin",
						Password: "supersecret"},
					Location: "testdata/valid",
				},
				{
					Secret: pgpass.Pgpass{Hostname: "prod.example.com",
						Port:     "5432",
						Database: "db",
						Username: "admin",
						Password: `pass\:word`},
					Location: "testdata/valid",
				},
			},
		}, {
			name:        "invalid .pgpass file",
			path:        "testdata/invalid",
			wantSecrets: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := pgpass.New()
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
			if err != nil {
				t.Fatalf("Extract() error = %v", err)
			}

			wantInv := inventory.Inventory{Secrets: tt.wantSecrets}
			if diff := cmp.Diff(wantInv, got); diff != "" {
				t.Errorf("Secret mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
