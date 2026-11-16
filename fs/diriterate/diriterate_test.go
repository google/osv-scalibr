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

package diriterate_test

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"testing/fstest"

	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/fs/diriterate"
)

func collectEntries(t *testing.T, it *diriterate.DirIterator) []string {
	t.Helper()
	var names []string
	for {
		d, err := it.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Next(): %v", err)
		}
		names = append(names, d.Name())
	}
	slices.Sort(names)
	return names
}

func TestReadDir_DirFS(t *testing.T) {
	root := t.TempDir()
	manyDir := filepath.Join(root, "many")
	if err := os.MkdirAll(manyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wantMany := make([]string, 0, 150)
	for i := range 150 {
		name := fmt.Sprintf("file-%03d.txt", i)
		wantMany = append(wantMany, name)
		if err := os.WriteFile(filepath.Join(manyDir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "regular.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	fsys := scalibrfs.DirFS(root)
	t.Cleanup(func() {
		if c, ok := fsys.(io.Closer); ok {
			_ = c.Close()
		}
	})

	t.Run("multi_batch_over_64_entries", func(t *testing.T) {
		it, err := diriterate.ReadDir(fsys, "many")
		if err != nil {
			t.Fatalf("ReadDir(many): %v", err)
		}
		defer func() { _ = it.Close() }()
		got := collectEntries(t, it)
		if !slices.Equal(got, wantMany) {
			t.Errorf("ReadDir(many) got %d entries, want %d", len(got), len(wantMany))
		}
	})

	t.Run("empty_directory", func(t *testing.T) {
		it, err := diriterate.ReadDir(fsys, "empty")
		if err != nil {
			t.Fatalf("ReadDir(empty): %v", err)
		}
		defer func() { _ = it.Close() }()
		got := collectEntries(t, it)
		if len(got) != 0 {
			t.Errorf("ReadDir(empty) = %v, want empty", got)
		}
	})

	t.Run("missing_directory", func(t *testing.T) {
		it, err := diriterate.ReadDir(fsys, "does-not-exist")
		if err == nil {
			_ = it.Close()
			t.Fatal("ReadDir(does-not-exist) succeeded, want fs.ErrNotExist")
		}
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("ReadDir(does-not-exist) err = %v, want fs.ErrNotExist", err)
		}
	})

	t.Run("regular_file_returns_non_eof_error", func(t *testing.T) {
		it, err := diriterate.ReadDir(fsys, "regular.txt")
		if err == nil {
			defer func() { _ = it.Close() }()
			_, err = it.Next()
		}
		if err == nil || errors.Is(err, io.EOF) {
			t.Errorf("ReadDir(regular.txt) err = %v, want non-EOF error", err)
		}
	})

	t.Run("permission_denied", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("chmod 0 does not deny directory reads on Windows or as root")
		}
		noPerm := filepath.Join(root, "noperm")
		if err := os.MkdirAll(noPerm, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(noPerm, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(noPerm, 0o700) })

		it, err := diriterate.ReadDir(fsys, "noperm")
		if err == nil {
			_ = it.Close()
			t.Fatal("ReadDir(noperm) succeeded, want fs.ErrPermission")
		}
		if !errors.Is(err, fs.ErrPermission) {
			t.Errorf("ReadDir(noperm) err = %v, want fs.ErrPermission", err)
		}
	})
}

type stubDirEntry struct {
	name string
}

func (s stubDirEntry) Name() string               { return s.name }
func (s stubDirEntry) IsDir() bool                { return false }
func (s stubDirEntry) Type() fs.FileMode          { return 0 }
func (s stubDirEntry) Info() (fs.FileInfo, error) { return nil, errors.New("unused") }

type nonReadDirFile struct{}

func (nonReadDirFile) Stat() (fs.FileInfo, error) { return nil, nil }
func (nonReadDirFile) Read([]byte) (int, error)   { return 0, io.EOF }
func (nonReadDirFile) Close() error               { return nil }

type fallbackFS struct {
	openErr error
	entries []fs.DirEntry
}

func (f fallbackFS) Open(string) (fs.File, error) {
	if f.openErr != nil {
		return nil, f.openErr
	}
	return nonReadDirFile{}, nil
}

func (f fallbackFS) ReadDir(string) ([]fs.DirEntry, error) {
	return f.entries, nil
}

func (f fallbackFS) Stat(string) (fs.FileInfo, error) {
	return nil, errors.New("unexpected Stat call")
}

type scriptedBatch struct {
	entries []fs.DirEntry
	err     error
}

type scriptedReadDirFile struct {
	batches []scriptedBatch
	idx     int
	closed  bool
}

func (s *scriptedReadDirFile) Stat() (fs.FileInfo, error) { return nil, nil }
func (s *scriptedReadDirFile) Read([]byte) (int, error)   { return 0, io.EOF }
func (s *scriptedReadDirFile) Close() error {
	s.closed = true
	return nil
}

func (s *scriptedReadDirFile) ReadDir(int) ([]fs.DirEntry, error) {
	if s.idx >= len(s.batches) {
		return nil, io.EOF
	}
	b := s.batches[s.idx]
	s.idx++
	return b.entries, b.err
}

type scriptedFS struct {
	file fs.ReadDirFile
}

func (s scriptedFS) Open(string) (fs.File, error)          { return s.file, nil }
func (s scriptedFS) ReadDir(string) ([]fs.DirEntry, error) { return nil, errors.New("unexpected") }
func (s scriptedFS) Stat(string) (fs.FileInfo, error)      { return nil, errors.New("unexpected") }

func TestReadDir_FallbacksAndBatches(t *testing.T) {
	t.Run("mapfs", func(t *testing.T) {
		mfs := fstest.MapFS{
			"dir/a.txt": &fstest.MapFile{Data: []byte("a")},
			"dir/b.txt": &fstest.MapFile{Data: []byte("b")},
		}
		it, err := diriterate.ReadDir(mfs, "dir")
		if err != nil {
			t.Fatalf("ReadDir(dir): %v", err)
		}
		defer func() { _ = it.Close() }()
		got := collectEntries(t, it)
		if want := []string{"a.txt", "b.txt"}; !slices.Equal(got, want) {
			t.Errorf("ReadDir(dir) = %v, want %v", got, want)
		}
	})

	t.Run("non_readdirfile_falls_back_to_readdir", func(t *testing.T) {
		fsys := fallbackFS{
			entries: []fs.DirEntry{stubDirEntry{name: "alpha"}, stubDirEntry{name: "beta"}},
		}
		it, err := diriterate.ReadDir(fsys, ".")
		if err != nil {
			t.Fatalf("ReadDir(.): %v", err)
		}
		defer func() { _ = it.Close() }()
		got := collectEntries(t, it)
		if want := []string{"alpha", "beta"}; !slices.Equal(got, want) {
			t.Errorf("ReadDir(.) = %v, want %v", got, want)
		}
	})

	t.Run("open_error_falls_back_to_readdir", func(t *testing.T) {
		fsys := fallbackFS{
			openErr: errors.New("cannot open directory"),
			entries: []fs.DirEntry{stubDirEntry{name: "only"}},
		}
		it, err := diriterate.ReadDir(fsys, ".")
		if err != nil {
			t.Fatalf("ReadDir(.): %v", err)
		}
		defer func() { _ = it.Close() }()
		got := collectEntries(t, it)
		if want := []string{"only"}; !slices.Equal(got, want) {
			t.Errorf("ReadDir(.) = %v, want %v", got, want)
		}
	})

	t.Run("partial_batch_with_eof_preserves_entries", func(t *testing.T) {
		file := &scriptedReadDirFile{
			batches: []scriptedBatch{
				{
					entries: []fs.DirEntry{stubDirEntry{name: "one"}, stubDirEntry{name: "two"}},
					err:     io.EOF,
				},
			},
		}
		it, err := diriterate.ReadDir(scriptedFS{file: file}, ".")
		if err != nil {
			t.Fatalf("ReadDir(.): %v", err)
		}
		got := collectEntries(t, it)
		if want := []string{"one", "two"}; !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
		if err := it.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
		if !file.closed {
			t.Error("expected underlying ReadDirFile to be closed")
		}
	})

	t.Run("partial_batch_with_error_yields_entries_before_error", func(t *testing.T) {
		wantErr := errors.New("injected read error")
		file := &scriptedReadDirFile{
			batches: []scriptedBatch{
				{
					entries: []fs.DirEntry{stubDirEntry{name: "first"}, stubDirEntry{name: "second"}},
					err:     wantErr,
				},
			},
		}
		it, err := diriterate.ReadDir(scriptedFS{file: file}, ".")
		if err != nil {
			t.Fatalf("ReadDir(.): %v", err)
		}
		defer func() { _ = it.Close() }()

		var got []string
		var gotErr error
		for {
			d, err := it.Next()
			if err != nil {
				gotErr = err
				break
			}
			got = append(got, d.Name())
		}
		if want := []string{"first", "second"}; !slices.Equal(got, want) {
			t.Errorf("entries before error = %v, want %v", got, want)
		}
		if !errors.Is(gotErr, wantErr) {
			t.Errorf("final err = %v, want %v", gotErr, wantErr)
		}
	})

	t.Run("empty_nil_batch_latches_eof", func(t *testing.T) {
		file := &scriptedReadDirFile{
			batches: []scriptedBatch{
				{entries: nil, err: nil},
				{entries: []fs.DirEntry{stubDirEntry{name: "should-not-read"}}, err: nil},
			},
		}
		it, err := diriterate.ReadDir(scriptedFS{file: file}, ".")
		if err != nil {
			t.Fatalf("ReadDir(.): %v", err)
		}
		defer func() { _ = it.Close() }()

		for call := range 2 {
			if _, err := it.Next(); !errors.Is(err, io.EOF) {
				t.Errorf("Next() call %d err = %v, want io.EOF", call, err)
			}
		}
		if file.idx != 1 {
			t.Errorf("ReadDir calls = %d, want 1 (EOF should be latched)", file.idx)
		}
	})
}
