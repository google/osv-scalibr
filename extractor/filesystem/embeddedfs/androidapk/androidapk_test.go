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

package androidapk_test

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/androidapk"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		desc                  string
		path                  string
		fileSize              int64
		maxFileSize           int64
		pluginSpecificMaxSize int64
		want                  bool
	}{
		{
			desc: "apk_lowercase",
			path: "testdata/app.apk",
			want: true,
		},
		{
			desc: "apk_uppercase",
			path: "testdata/APP.APK",
			want: true,
		},
		{
			desc: "not_apk",
			path: "testdata/document.txt",
			want: false,
		},
		{
			desc: "no_extension",
			path: "testdata/noextension",
			want: false,
		},
		{
			desc:        "file_size_below_limit",
			path:        "app.apk",
			fileSize:    1000,
			maxFileSize: 1000,
			want:        true,
		},
		{
			desc:        "file_size_above_limit",
			path:        "app.apk",
			fileSize:    1001,
			maxFileSize: 1000,
			want:        false,
		},
		{
			desc:                  "override_global_size_below_limit",
			path:                  "app.apk",
			fileSize:              1001,
			maxFileSize:           1000,
			pluginSpecificMaxSize: 1001,
			want:                  true,
		},
		{
			desc:                  "override_global_size_above_limit",
			path:                  "app.apk",
			fileSize:              1001,
			maxFileSize:           1001,
			pluginSpecificMaxSize: 1000,
			want:                  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			extractor, err := androidapk.New(&cpb.PluginConfig{
				MaxFileSizeBytes: tt.maxFileSize,
				PluginSpecific: []*cpb.PluginSpecificConfig{
					{
						Config: &cpb.PluginSpecificConfig_AndroidApk{
							AndroidApk: &cpb.AndroidApkConfig{
								MaxFileSizeBytes: tt.pluginSpecificMaxSize,
							},
						},
					},
				},
			})
			if err != nil {
				t.Fatalf("androidapk.New: %v", err)
			}

			got := extractor.FileRequired(simplefileapi.New(
				tt.path,
				fakefs.FakeFileInfo{
					FileSize: tt.fileSize,
				},
			))

			if got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtractValidAPK(t *testing.T) {
	extractor, err := androidapk.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("androidapk.New: %v", err)
	}

	path := filepath.FromSlash("testdata/split_CronetDynamite_installtime.apk")

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat(%q) failed: %v", path, err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("os.Open(%q) failed: %v", path, err)
	}
	defer f.Close()

	input := &filesystem.ScanInput{
		Path:   path,
		Root:   ".",
		Info:   info,
		Reader: f,
		FS:     nil,
	}

	ctx := t.Context()

	inv, err := extractor.Extract(ctx, input)
	if err != nil {
		t.Fatalf("Extract(%q) failed: %v", path, err)
	}

	if len(inv.EmbeddedFSs) == 0 {
		t.Fatal("Extract returned no EmbeddedFSs")
	}

	if len(inv.Packages) == 0 {
		t.Fatal("Extract returned no Packages")
	}

	foundManifestPackage := false
	for _, pkg := range inv.Packages {
		if strings.Contains(pkg.Name, "google") {
			foundManifestPackage = true
			break
		}
	}

	if !foundManifestPackage {
		t.Errorf("Expected at least one package related to Google")
	}

	for _, embeddedFS := range inv.EmbeddedFSs {
		if embeddedFS.Path != path {
			t.Errorf("EmbeddedFS.Path = %q, want %q", embeddedFS.Path, path)
		}

		fs, err := embeddedFS.GetEmbeddedFS(ctx)
		if err != nil {
			t.Fatalf("GetEmbeddedFS() failed: %v", err)
		}

		entries, err := fs.ReadDir("/")
		if err != nil {
			t.Fatalf("fs.ReadDir(/) failed: %v", err)
		}

		if len(entries) == 0 {
			t.Errorf("fs.ReadDir(/) returned no entries")
		}

		info, err := fs.Stat("/")
		if err != nil {
			t.Fatalf("fs.Stat(/) failed: %v", err)
		}

		if !info.IsDir() {
			t.Errorf("fs.Stat(/).IsDir() = %v, want true", info.IsDir())
		}

		foundManifest := false

		for _, entry := range entries {
			name := entry.Name()

			if name == "AndroidManifest.xml" {
				foundManifest = true

				manifestFile, err := fs.Open(name)
				if err != nil {
					t.Fatalf("fs.Open(%q) failed: %v", name, err)
				}

				data, err := io.ReadAll(manifestFile)
				manifestFile.Close()

				if err != nil {
					t.Fatalf("io.ReadAll(%q) failed: %v", name, err)
				}

				if len(data) == 0 {
					t.Errorf("%q is empty", name)
				}

				break
			}
		}

		if !foundManifest {
			t.Errorf("AndroidManifest.xml not found in embedded filesystem")
		}
	}
}

func TestExtractInvalidAPK(t *testing.T) {
	extractor, err := androidapk.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("androidapk.New: %v", err)
	}

	tmpFile, err := os.CreateTemp(t.TempDir(), "*.apk")
	if err != nil {
		t.Fatalf("os.CreateTemp() failed: %v", err)
	}

	if _, err := tmpFile.WriteString("this is not a valid apk"); err != nil {
		t.Fatalf("tmpFile.WriteString() failed: %v", err)
	}

	if err := tmpFile.Close(); err != nil {
		t.Fatalf("tmpFile.Close() failed: %v", err)
	}

	info, err := os.Stat(tmpFile.Name())
	if err != nil {
		t.Fatalf("os.Stat(%q) failed: %v", tmpFile.Name(), err)
	}

	f, err := os.Open(tmpFile.Name())
	if err != nil {
		t.Fatalf("os.Open(%q) failed: %v", tmpFile.Name(), err)
	}
	defer f.Close()

	input := &filesystem.ScanInput{
		Path:   tmpFile.Name(),
		Root:   ".",
		Info:   info,
		Reader: f,
		FS:     nil,
	}

	ctx := t.Context()

	_, err = extractor.Extract(ctx, input)
	if err == nil {
		t.Errorf("Extract(%q) succeeded, want error", tmpFile.Name())
	}
}

func TestExtractNilReader(t *testing.T) {
	extractor, err := androidapk.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("androidapk.New: %v", err)
	}

	input := &filesystem.ScanInput{
		Path:   "testdata/split_CronetDynamite_installtime.apk",
		Root:   ".",
		Info:   nil,
		Reader: nil,
		FS:     nil,
	}

	ctx := t.Context()

	_, err = extractor.Extract(ctx, input)
	if err == nil {
		t.Fatal("Extract() succeeded, want error")
	}

	if !strings.Contains(err.Error(), "input.Reader is nil") {
		t.Errorf("unexpected error: %v", err)
	}
}
