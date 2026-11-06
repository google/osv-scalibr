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

package osrelease_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"testing/fstest"

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
			name: "ignore_comments",
			path: "etc/os-release",
			content: `#ID=foo
			ID=ubuntu`,
			mode: 0666,
			want: map[string]string{"ID": "ubuntu"},
		},
		{
			name: "ignore_random_stuff",
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
			_ = os.Mkdir(filepath.Join(d, "etc"), 0744)
			_ = os.MkdirAll(filepath.Join(d, "usr/lib"), 0744)
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

func TestNotAnOS(t *testing.T) {
	d := t.TempDir()

	got, err := osrelease.GetOSRelease(scalibrfs.DirFS(d))
	if !errors.Is(err, osrelease.ErrNotADistro) {
		t.Fatalf("Got unexpected error on empty FS: %v", err)
	}
	if got != nil {
		t.Fatalf("Got OS data on empty FS: %+v", got)
	}
}

// wrapErrFS wraps errors the way the container image layer FS does.
type wrapErrFS struct {
	scalibrfs.FS
}

func (w wrapErrFS) Open(name string) (fs.File, error) {
	f, err := w.FS.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get virtual file to open %s: %w", name, err)
	}
	return f, nil
}

func (w wrapErrFS) Stat(name string) (fs.FileInfo, error) {
	fi, err := w.FS.Stat(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get virtual file to stat %s: %w", name, err)
	}
	return fi, nil
}

func TestGetOSReleaseWrappedNotExistError(t *testing.T) {
	tests := []struct {
		name    string
		files   fstest.MapFS
		want    map[string]string
		wantErr error
	}{
		{
			name:  "falls back to usr/lib/os-release",
			files: fstest.MapFS{"etc/hostname": {Data: []byte("h")}, "usr/lib/os-release": {Data: []byte("ID=debian\nVERSION_ID=12")}},
			want:  map[string]string{"ID": "debian", "VERSION_ID": "12"},
		},
		{
			name: "etc/os-release wins when both exist",
			files: fstest.MapFS{
				"etc/os-release":     {Data: []byte("ID=alpine")},
				"usr/lib/os-release": {Data: []byte("ID=debian")},
			},
			want: map[string]string{"ID": "alpine"},
		},
		{
			name:    "neither file exists",
			files:   fstest.MapFS{"etc/hostname": {Data: []byte("h")}},
			wantErr: os.ErrNotExist,
		},
		{
			name:    "no etc dir is not a distro",
			files:   fstest.MapFS{"foo": {Data: []byte("x")}},
			wantErr: osrelease.ErrNotADistro,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := osrelease.GetOSRelease(wrapErrFS{tt.files})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetOSRelease() error: got %v, want %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("GetOSRelease() (-want +got):\n%s", diff)
			}
		})
	}
}
