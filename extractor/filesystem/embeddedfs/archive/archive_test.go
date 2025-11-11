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
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/archive"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		desc        string
		path        string
		fileSize    int64
		maxFileSize int64
		want        bool
	}{
		{
			desc: "tar.gz",
			path: "archive.tar.gz",
			want: true,
		},
		{
			desc: "tar",
			path: "archive.tar",
			want: true,
		},
		{
			desc: "unsupported_extension",
			path: "document.txt",
			want: false,
		},
		{
			desc: "no_extension",
			path: "noextension",
			want: false,
		},
		{
			desc:        "file_size_below_limit",
			path:        "archive.tar.gz",
			fileSize:    1000,
			maxFileSize: 1000,
			want:        true,
		},
		{
			desc:        "file_size_above_limit",
			path:        "archive.tar.gz",
			fileSize:    1001,
			maxFileSize: 1000,
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			e := archive.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSize})
			if got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileSize: tt.fileSize,
			})); got != tt.want {
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
			e := archive.New(&cpb.PluginConfig{})
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
