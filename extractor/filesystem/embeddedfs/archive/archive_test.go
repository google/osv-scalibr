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

package archive_test

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/archive"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"archive.tar.gz", true},
		{"archive.tar", true},
		{"document.txt", false},
		{"noextension", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := archive.New().FileRequired(simplefileapi.New(tt.path, nil)); got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name        string
		inputConfig extracttest.ScanInputMockConfig
		wantFiles   map[string]string
		wantErr     error
	}{
		{
			name: "regular_tar",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/archive.tar",
			},
			wantFiles: map[string]string{"file.txt": "tar contents"},
		},
		{
			name: "gzipped_tar",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/archive.tar.gz",
			},
			wantFiles: map[string]string{"file.txt": "tar.gz contents"},
		},
		{
			name: "not_an_archive",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-an-archive.txt",
			},
			wantErr: cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := archive.New()
			scanInput := extracttest.GenerateScanInputMock(t, tt.inputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			inv, err := e.Extract(t.Context(), &scanInput)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.name, err, tt.wantErr)
			}

			if tt.wantErr == nil && len(inv.EmbeddedFSs) == 0 {
				t.Fatal("No embedded FS returned")
			}

			for i, embeddedFS := range inv.EmbeddedFSs {
				t.Run(fmt.Sprintf("archive_%d", i), func(t *testing.T) {
					fs, err := embeddedFS.GetEmbeddedFS(t.Context())
					if err != nil {
						t.Errorf("GetEmbeddedFS(): %v", err)
					}

					if _, err := fs.ReadDir("/"); err != nil {
						t.Fatalf("fs.ReadDir(/): %v", err)
					}
					if _, err := fs.Stat("/"); err != nil {
						t.Fatalf("fs.Stat(/): %v", err)
					}

					for wantPath, wantContent := range tt.wantFiles {
						f, err := fs.Open(wantPath)
						if err != nil {
							t.Fatalf("fs.Open(%q): %v", wantPath, err)
						}
						defer f.Close()

						bytes, err := io.ReadAll(f)
						if err != nil {
							t.Fatalf("ReadAll: %v", err)
						}

						if !strings.HasPrefix(string(bytes), wantContent) {
							t.Fatalf("got %q content: %q, want %q", wantPath, string(bytes), wantContent)
						}
					}
				})
			}
		})
	}
}
