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

package mongodbatlasrefreshtoken_test

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/mongodbatlasrefreshtoken"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/testing/fakefs"
	velesmongodbatlas "github.com/google/osv-scalibr/veles/secrets/mongodbatlasrefreshtoken"
)

const testRefreshToken = "ZkHO9xXUOXx_A6gAJyqQZX5EJZUTG5c75tAkwd22als"

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantScan bool
	}{
		{
			name:     "atlascli config.toml",
			path:     "/home/user/.config/atlascli/config.toml",
			wantScan: true,
		},
		{
			name:     "atlascli config.toml in different location",
			path:     "/etc/atlascli/config.toml",
			wantScan: true,
		},
		{
			name:     "random config.toml",
			path:     "/project/config.toml",
			wantScan: false,
		},
		{
			name:     "random file",
			path:     "/home/user/document.txt",
			wantScan: false,
		},
		{
			name:     "package.json",
			path:     "/project/package.json",
			wantScan: false,
		},
		{
			name:     ".env file",
			path:     "/project/.env",
			wantScan: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := mongodbatlasrefreshtoken.New(nil)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			got := e.FileRequired(simplefileapi.New(tt.path, nil))
			if got != tt.wantScan {
				t.Errorf("FileRequired() = %v, want %v", got, tt.wantScan)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		content string
		want    inventory.Inventory
	}{
		{
			name: "MongoDB Atlas refresh token in atlascli config",
			path: "atlascli/config.toml",
			content: `[default]
org_id = "abc123"
refresh_token = '` + testRefreshToken + `'
`,
			want: inventory.Inventory{
				Secrets: []*inventory.Secret{
					{
						Location: "atlascli/config.toml",
						Secret:   velesmongodbatlas.MongoDBAtlasRefreshToken{Token: testRefreshToken},
					},
				},
			},
		},
		{
			name: "No token in file",
			path: "atlascli/config.toml",
			content: `[default]
org_id = "abc123"
project_id = "def456"`,
			want: inventory.Inventory{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := mongodbatlasrefreshtoken.New(nil)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			r := strings.NewReader(tt.content)
			input := &filesystem.ScanInput{
				Path:   tt.path,
				Reader: io.NopCloser(r),
				Root:   "/",
				FS:     scalibrfs.DirFS("/"),
				Info:   &fakefs.FakeFileInfo{FileName: tt.path},
			}

			got, err := e.Extract(context.Background(), input)
			if err != nil {
				t.Fatalf("Extract() error = %v", err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Extract() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNew(t *testing.T) {
	e, err := mongodbatlasrefreshtoken.New(nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if e.Name() != mongodbatlasrefreshtoken.Name {
		t.Errorf("Name() = %v, want %v", e.Name(), mongodbatlasrefreshtoken.Name)
	}

	if e.Version() != mongodbatlasrefreshtoken.Version {
		t.Errorf("Version() = %v, want %v", e.Version(), mongodbatlasrefreshtoken.Version)
	}
}
