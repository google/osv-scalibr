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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/testing/extracttest"
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
		Name        string
		InputConfig extracttest.ScanInputMockConfig
		WantSecrets []*inventory.Secret
		WantErr     error
	}{
		{
			Name: "valid .pgpass file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid",
			},
			WantSecrets: []*inventory.Secret{
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
					Secret: pgpass.Pgpass{Hostname: "hostname",
						Port:     "1234",
						Database: "testdb",
						Username: "testuser",
						Password: "passw ord"},
					Location: "testdata/valid",
				},
				{
					Secret: pgpass.Pgpass{Hostname: "hostname",
						Port:     "1234",
						Database: "db name",
						Username: "testuser",
						Password: "password"},
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
			Name: "invalid .pgpass file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid",
			},
			WantSecrets: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			e := pgpass.New()
			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := e.Extract(t.Context(), &scanInput)
			if err != nil {
				t.Fatalf("%s.Extract(%q) failed: %v", e.Name(), tt.InputConfig.Path, err)
			}

			wantInv := inventory.Inventory{Secrets: tt.WantSecrets}
			if diff := cmp.Diff(wantInv, got); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", e.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
