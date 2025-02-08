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
