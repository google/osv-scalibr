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

package osrelease_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

func TestGetOSRelease(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		content       string
		mode          os.FileMode
		want          map[string]string
		wantErr       error
		skipOnWindows bool
	}{
		{
			name:    "location: etc/os-release",
			path:    "etc/os-release",
			content: `ID=ubuntu`,
			mode:    0666,
			want:    map[string]string{"ID": "ubuntu"},
		},
		{
			name:    "location: usr/lib/os-release",
			path:    "usr/lib/os-release",
			content: `ID=ubuntu`,
			mode:    0666,
			want:    map[string]string{"ID": "ubuntu"},
		},
		{
			name:    "not found",
			path:    "foo",
			content: `ID=ubuntu`,
			mode:    0666,
			wantErr: os.ErrNotExist,
		},
		{
			name:          "permission error",
			path:          "etc/os-release",
			content:       `ID=ubuntu`,
			mode:          0,
			wantErr:       os.ErrPermission,
			skipOnWindows: true,
		},
		{
			name: "ignore comments",
			path: "etc/os-release",
			content: `#ID=foo
			ID=ubuntu`,
			mode: 0666,
			want: map[string]string{"ID": "ubuntu"},
		},
		{
			name: "ignore random stuff",
			path: "etc/os-release",
			content: `random stuff
			ID=ubuntu`,
			mode: 0666,
			want: map[string]string{"ID": "ubuntu"},
		},
		{
			name:    "resolve quotes",
			path:    "etc/os-release",
			content: `ID="ubuntu"`,
			mode:    0666,
			want:    map[string]string{"ID": "ubuntu"},
		},
		{
			name:    "don't resolve partial quotes",
			path:    "etc/os-release",
			content: `ID="ubuntu`,
			mode:    0666,
			want:    map[string]string{"ID": "\"ubuntu"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipOnWindows && runtime.GOOS == "windows" {
				t.Skip()
			}

			d := t.TempDir()
			os.Mkdir(filepath.Join(d, "etc"), 0744)
			os.MkdirAll(filepath.Join(d, "usr/lib"), 0744)
			p := filepath.Join(d, tt.path)
			err := os.WriteFile(p, []byte(tt.content), tt.mode)
			if err != nil {
				t.Fatalf("WriteFile(%s): %v", tt.path, err)
			}

			got, err := osrelease.GetOSRelease(scalibrfs.DirFS(d))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("FileRequired(%s) error: got %v, want %v", tt.path, err, tt.wantErr)
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
