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

package rpmfile_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	rpmmeta "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpmfile"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/fakefs"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		size         int64
		maxSize      int64
		wantRequired bool
	}{
		{
			name:         "rpm file",
			path:         "foo.rpm",
			size:         1024,
			wantRequired: true,
		},
		{
			name:         "not rpm",
			path:         "foo.txt",
			size:         1024,
			wantRequired: false,
		},
		{
			name:         "size below limit",
			path:         "foo.rpm",
			size:         100,
			maxSize:      1000,
			wantRequired: true,
		},
		{
			name:         "size above limit",
			path:         "foo.rpm",
			size:         2000,
			maxSize:      1000,
			wantRequired: false,
		},
		{
			name:         "no limit",
			path:         "foo.rpm",
			size:         5000,
			maxSize:      0,
			wantRequired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := rpmfile.New(&cpb.PluginConfig{
				MaxFileSizeBytes: tt.maxSize,
			})
			if err != nil {
				t.Fatal(err)
			}

			got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileSize: tt.size,
			}))

			if got != tt.wantRequired {
				t.Fatalf("FileRequired(%q)=%v want %v", tt.path, got, tt.wantRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unsupported on windows")
	}

	f, err := os.Open("testdata/aws-tools-26.0.0-4.fc44.x86_64.rpm")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}

	e, err := rpmfile.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatal(err)
	}

	got, err := e.Extract(t.Context(), &filesystem.ScanInput{
		Path:   "testdata/aws-tools-26.0.0-4.fc44.x86_64.rpm",
		Reader: f,
		Info:   info,
	})
	if err != nil {
		t.Fatalf("Extract() returned error: %v", err)
	}

	if len(got.Packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(got.Packages))
	}

	want := &extractor.Package{
		Name:     "aws-tools",
		Version:  "26.0.0-4.fc44",
		PURLType: purl.TypeRPM,
		Location: extractor.LocationFromPath("testdata/aws-tools-26.0.0-4.fc44.x86_64.rpm"),
		Metadata: &rpmmeta.Metadata{
			PackageName:  "aws-tools",
			SourceRPM:    "aws-26.0.0-4.fc44.src.rpm",
			Epoch:        2,
			Architecture: "x86_64",
			Vendor:       "Fedora Project",
		},
		Licenses: []string{"GPL-3.0-or-later AND (GPL-3.0-or-later WITH GCC-exception-3.1 OR GPL-3.0-or-later WITH GNAT-exception)"},
	}

	if diff := cmp.Diff(want, got.Packages[0]); diff != "" {
		t.Errorf("Extract() mismatch (-want +got):\n%s", diff)
	}
}
