package fakefs

import (
	"io/fs"
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
