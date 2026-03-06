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

package fakefs

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

func TestPrepareFS(t *testing.T) {
	tests := []struct {
		name     string
		txt      string
		mod      FileModifier
		wantErr  bool
		validate func(t *testing.T, fsys fs.FS)
	}{
		{
			name: "regular_files",
			txt: `
-- file1.txt --
content1
-- dir/file2.txt --
content2
`,
			validate: func(t *testing.T, fsys fs.FS) {
				data, err := fs.ReadFile(fsys, "file1.txt")
				if err != nil || string(data) != "content1" {
					t.Errorf("ReadFile(file1.txt) = %q, %v; want 'content1', nil", data, err)
				}
				data, err = fs.ReadFile(fsys, "file2.txt")
				if err != nil || string(data) != "content2" {
					t.Errorf("ReadFile(file1.txt) = %q, %v; want 'content1', nil", data, err)
				}
			},
		},
		{
			name: "empty_directory_detection",
			txt: `
-- empty-dir/ --
`,
			validate: func(t *testing.T, fsys fs.FS) {
				info, err := fs.Stat(fsys, "empty-dir")
				if err != nil {
					t.Fatalf("Stat(empty-dir) failed: %v", err)
				}
				if !info.IsDir() {
					t.Error("expected empty-dir to be a directory")
				}
			},
		},
		{
			name: "modifier_application",
			txt: `
-- secret.txt --
plain
`,
			mod: func(name string, f *fstest.MapFile) error {
				if name == "secret.txt" {
					f.Data = []byte("encrypted")
				}
				return nil
			},
			validate: func(t *testing.T, fsys fs.FS) {
				data, _ := fs.ReadFile(fsys, "secret.txt")
				if string(data) != "encrypted" {
					t.Errorf("Modifier did not apply, got %q", data)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mods []FileModifier
			if tt.mod != nil {
				mods = append(mods, tt.mod)
			}

			fsys, err := PrepareFS(tt.txt, mods...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("PrepareFS() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.validate != nil {
				tt.validate(t, fsys)
			}

			// Native Go check: verifies the FS is valid according to io/fs rules.
			if err := fstest.TestFS(fsys); err != nil {
				t.Errorf("fstest.TestFS validation failed: %v", err)
			}
		})
	}
}
