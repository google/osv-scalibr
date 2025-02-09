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

package whiteout_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/artifact/image/whiteout"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

func TestWhiteout(t *testing.T) {
	testCases := []struct {
		desc  string
		paths []string
		dirs  []string
		want  map[string]struct{}
	}{
		{
			desc:  "Empty filesystem",
			paths: []string{},
			dirs:  []string{},
			want:  map[string]struct{}{},
		},
		{
			desc: "Single regular file",
			paths: []string{
				"hello_world.txt",
			},
			dirs: []string{},
			want: map[string]struct{}{},
		},
		{
			desc: "Single whiteout file",
			paths: []string{
				".wh.hello_world.txt",
			},
			dirs: []string{},
			want: map[string]struct{}{
				".wh.hello_world.txt": {},
			},
		},
		{
			desc: "Mix of regular and whiteout files",
			paths: []string{
				"hello_world.txt",
				".wh.foo.txt",
				".wh.bar.txt",
			},
			dirs: []string{},
			want: map[string]struct{}{
				".wh.foo.txt": {},
				".wh.bar.txt": {},
			},
		},
		{
			desc: "Mix of regular and whiteout files in different directories",
			paths: []string{
				"hello_world.txt",
				"/dir1/.wh.foo.txt",
				"/dir2/.wh.bar.txt",
			},
			dirs: []string{
				"dir1",
				"dir2",
			},
			want: map[string]struct{}{
				"dir1/.wh.foo.txt": {},
				"dir2/.wh.bar.txt": {},
			},
		},
		{
			desc: "Single whiteout directory",
			paths: []string{
				".wh..wh..opa.dir1",
			},
			dirs: []string{
				"dir1",
			},
			want: map[string]struct{}{
				".wh..wh..opa.dir1": {},
			},
		},
		{
			desc: "Mix of regular and whiteout files / directory",
			paths: []string{
				".wh..wh..opa.dir1",
				".wh..wh..opa.dir2",
				"/dir3/foo.txt",
				"/dir3/dir4/.wh.bar.txt",
			},
			dirs: []string{
				"dir1",
				"dir2",
				"dir3/dir4",
			},
			want: map[string]struct{}{
				".wh..wh..opa.dir1":     {},
				".wh..wh..opa.dir2":     {},
				"dir3/dir4/.wh.bar.txt": {},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			tmp := t.TempDir()
			fs := scalibrfs.DirFS(tmp)

			// Create directories first, then write files to fs.
			for _, dir := range tc.dirs {
				err := os.MkdirAll(filepath.Join(tmp, dir), 0777)
				if err != nil {
					t.Fatalf("os.MkdirAll(%q): unexpected error: %v", filepath.Join(tmp, dir), err)
				}
			}

			for _, path := range tc.paths {
				err := os.WriteFile(filepath.Join(tmp, path), []byte("Content"), 0644)
				if err != nil {
					t.Fatalf("os.WriteFile(%q): unexpected error: %v", filepath.Join(tmp, path), err)
				}
			}

			got, err := whiteout.Files(fs)
			if err != nil {
				t.Fatalf("whiteout.Files(%v): unexpected error: %v", fs, err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("whiteout.Files(%v): unexpected diff (-want +got):\n%s", fs, diff)
			}
		})
	}
}

func TestIsWhiteout(t *testing.T) {
	testCases := []struct {
		desc string
		path string
		want bool
	}{
		{
			desc: "Empty path",
			path: "",
			want: false,
		},
		{
			desc: "Simple file path",
			path: "file.txt",
			want: false,
		},
		{
			desc: "Path with directories",
			path: "dir1/dir2/foo.txt",
			want: false,
		},
		{
			desc: "Simple whiteout path",
			path: ".wh.file.txt",
			want: true,
		},
		{
			desc: "Whiteout path with directories",
			path: "dir1/dir2/.wh.foo.txt",
			want: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := whiteout.IsWhiteout(tc.path)
			if got != tc.want {
				t.Errorf("IsWhiteout(%q) = %v, want: %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestToWhiteout(t *testing.T) {
	testCases := []struct {
		desc string
		path string
		want string
	}{
		{
			desc: "Empty path",
			path: "",
			want: ".wh.",
		},
		{
			desc: "Simple file path",
			path: "file.txt",
			want: ".wh.file.txt",
		},
		{
			desc: "Path with directories",
			path: "dir1/dir2/foo.txt",
			want: "dir1/dir2/.wh.foo.txt",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := whiteout.ToWhiteout(tc.path)
			if got != tc.want {
				t.Errorf("ToWhiteout(%q) = %q, want: %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestToPath(t *testing.T) {
	testCases := []struct {
		desc string
		path string
		want string
	}{
		{
			desc: "Empty path",
			path: "",
			want: "",
		},
		{
			desc: "Simple file path",
			path: "file.txt",
			want: "file.txt",
		},
		{
			desc: "Path with directories",
			path: "dir1/dir2/foo.txt",
			want: "dir1/dir2/foo.txt",
		},
		{
			desc: "Simple whiteout path",
			path: ".wh.file.txt",
			want: "file.txt",
		},
		{
			desc: "Whiteout path with directories",
			path: "dir1/dir2/.wh.foo.txt",
			want: "dir1/dir2/foo.txt",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := whiteout.ToPath(tc.path)
			if got != tc.want {
				t.Errorf("ToPath(%q) = %q, want: %q", tc.path, got, tc.want)
			}
		})
	}
}
