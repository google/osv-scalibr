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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
)

func TestPrepareFS(t *testing.T) {
	tests := []struct {
		name     string
		txt      string
		mod      FileModifier
		wantErr  bool
		expected []string
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
			expected: []string{"file1.txt", "dir", "dir/file2.txt"},
			validate: func(t *testing.T, fsys fs.FS) {
				t.Helper()

				data1, err := fs.ReadFile(fsys, "file1.txt")
				if err != nil {
					t.Fatalf("failed to read file1.txt: %v", err)
				}
				if diff := cmp.Diff("content1\n", string(data1)); diff != "" {
					t.Errorf("file1.txt content mismatch (-want +got):\n%s", diff)
				}
				data2, err := fs.ReadFile(fsys, "dir/file2.txt")
				if err != nil {
					t.Fatalf("failed to read dir/file2.txt: %v", err)
				}
				if diff := cmp.Diff("content2\n", string(data2)); diff != "" {
					t.Errorf("dir/file2.txt content mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			name: "empty_directory",
			txt: `
-- empty-dir/ --
`,
			expected: []string{"empty-dir"},
			validate: func(t *testing.T, fsys fs.FS) {
				t.Helper()

				info, err := fs.Stat(fsys, "empty-dir")
				if err != nil {
					t.Fatalf("Stat(empty-dir) failed: %v", err)
				}
				if !info.IsDir() {
					t.Error("expected empty-dir to be a directory, but IsDir() is false")
				}
			},
		},
		{
			name: "modifier_application",
			txt: `
-- secret.txt --
plain
`,
			expected: []string{"secret.txt"},
			mod: func(name string, f *fstest.MapFile) error {
				if name == "secret.txt" {
					f.Data = []byte("encrypted")
				}
				return nil
			},
			validate: func(t *testing.T, fsys fs.FS) {
				t.Helper()
				data, err := fs.ReadFile(fsys, "secret.txt")
				if err != nil {
					t.Fatalf("failed to read secret.txt: %v", err)
				}
				if diff := cmp.Diff("encrypted", string(data)); diff != "" {
					t.Errorf("modifier not applied (-want +got):\n%s", diff)
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

			if err := fstest.TestFS(fsys, tt.expected...); err != nil {
				t.Errorf("fstest.TestFS validation failed: %v", err)
			}
		})
	}
}

func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require additional privileges on Windows")
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("os.MkdirAll(%q): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("os.WriteFile(%q): %v", path, err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0755); err != nil {
		t.Fatalf("os.MkdirAll(%q): %v", filepath.Dir(link), err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("os.Symlink(%q, %q): %v", target, link, err)
	}
}

func TestCopyTestData(t *testing.T) {
	skipOnWindows(t)

	tests := []struct {
		name string
		// setup creates the source tree and returns the srcDir to copy.
		setup func(t *testing.T) string
		// want maps slash-separated paths in the copy to their expected content.
		want map[string]string
	}{
		{
			name: "regular_file",
			setup: func(t *testing.T) string {
				t.Helper()
				src := t.TempDir()
				mustWriteFile(t, filepath.Join(src, "sub", "a.txt"), "a")
				return src
			},
			want: map[string]string{"sub/a.txt": "a"},
		},
		{
			name: "file_symlink",
			setup: func(t *testing.T) string {
				t.Helper()
				outside := filepath.Join(t.TempDir(), "real.txt")
				mustWriteFile(t, outside, "hello")
				src := t.TempDir()
				mustSymlink(t, outside, filepath.Join(src, "sub", "linked.txt"))
				return src
			},
			want: map[string]string{"sub/linked.txt": "hello"},
		},
		{
			name: "dir_symlink",
			setup: func(t *testing.T) string {
				t.Helper()
				outsideDir := t.TempDir()
				mustWriteFile(t, filepath.Join(outsideDir, "nested", "b.txt"), "b")
				src := t.TempDir()
				mustSymlink(t, outsideDir, filepath.Join(src, "linkeddir"))
				return src
			},
			want: map[string]string{"linkeddir/nested/b.txt": "b"},
		},
		{
			name: "src_dir_is_symlink",
			setup: func(t *testing.T) string {
				t.Helper()
				realDir := t.TempDir()
				mustWriteFile(t, filepath.Join(realDir, "c.txt"), "c")
				link := filepath.Join(t.TempDir(), "srclink")
				mustSymlink(t, realDir, link)
				return link
			},
			want: map[string]string{"c.txt": "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copiedDir := CopyTestData(t, tt.setup(t))
			root, err := os.OpenRoot(copiedDir)
			if err != nil {
				t.Fatalf("os.OpenRoot(%q): %v", copiedDir, err)
			}
			defer root.Close()

			for name, want := range tt.want {
				info, err := root.Lstat(name)
				if err != nil {
					t.Fatalf("root.Lstat(%q): %v", name, err)
				}
				if !info.Mode().IsRegular() {
					t.Errorf("root.Lstat(%q).Mode() = %v, want regular file", name, info.Mode())
				}
				got, err := root.ReadFile(name)
				if err != nil {
					t.Fatalf("root.ReadFile(%q): %v", name, err)
				}
				if diff := cmp.Diff(want, string(got)); diff != "" {
					t.Errorf("root.ReadFile(%q) mismatch (-want +got):\n%s", name, diff)
				}
			}
		})
	}
}

func TestCopyTestDataReadOnlySourceIsWritable(t *testing.T) {
	src := t.TempDir()
	path := filepath.Join(src, "ro.txt")
	mustWriteFile(t, path, "ro")
	if err := os.Chmod(path, 0444); err != nil {
		t.Fatalf("os.Chmod(%q): %v", path, err)
	}

	copied := filepath.Join(CopyTestData(t, src), "ro.txt")
	if err := os.WriteFile(copied, []byte("rw"), 0644); err != nil {
		t.Errorf("os.WriteFile(%q) on copy of read-only file: %v", copied, err)
	}
}

func TestCreateSymlinkEscapeFixtureRejectedByOSRoot(t *testing.T) {
	skipOnWindows(t)

	scanRoot, outsidePath := CreateSymlinkEscapeFixture(t, "nested/escape.txt")

	// The link must really resolve to the outside file, otherwise the check
	// below could pass for an unrelated reason such as a dangling link.
	linkPath := filepath.Join(scanRoot, "nested", "escape.txt")
	got, err := os.ReadFile(linkPath)
	if err != nil {
		t.Fatalf("os.ReadFile(%q): %v", linkPath, err)
	}
	if string(got) != OutsideFileContent {
		t.Fatalf("os.ReadFile(%q) = %q, want %q", linkPath, got, OutsideFileContent)
	}
	if strings.HasPrefix(outsidePath, scanRoot+string(filepath.Separator)) {
		t.Fatalf("outsidePath %q is inside scanRoot %q", outsidePath, scanRoot)
	}

	root, err := os.OpenRoot(scanRoot)
	if err != nil {
		t.Fatalf("os.OpenRoot(%q): %v", scanRoot, err)
	}
	defer root.Close()

	f, err := root.Open("nested/escape.txt")
	if err == nil {
		f.Close()
		t.Fatal("root.Open(nested/escape.txt) succeeded, want symlink escape error")
	}
	// os.Root's escape error is unexported, so match on its message.
	if !strings.Contains(err.Error(), "path escapes from parent") {
		t.Errorf("root.Open(nested/escape.txt) error = %v, want path escape error", err)
	}
}
