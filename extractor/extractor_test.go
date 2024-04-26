// Copyright 2024 Google LLC
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

package extractor_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"
	fe "github.com/google/osv-scalibr/testing/fakeextractor"
)

func TestRun(t *testing.T) {
	success := &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}
	path1 := "dir1/file1.txt"
	path2 := "dir2/sub/file2.txt"
	fsys := fstest.MapFS{
		".":                  {Mode: fs.ModeDir},
		"dir1":               {Mode: fs.ModeDir},
		"dir2":               {Mode: fs.ModeDir},
		"dir1/file1.txt":     {Data: []byte("Content 1")},
		"dir2/sub/file2.txt": {Data: []byte("Content 2")},
	}
	name1 := "software1"
	name2 := "software2"

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd(): %v", err)
	}

	testCases := []struct {
		desc           string
		ex             []extractor.InventoryExtractor
		dirsToSkip     []string
		skipDirRegex   string
		maxInodes      int
		wantErr        error
		wantInv        []*extractor.Inventory
		wantStatus     []*plugin.Status
		wantInodeCount int
	}{
		{
			desc: "Extractors successful",
			ex: []extractor.InventoryExtractor{
				fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: []string{name1}, Err: nil}}),
				fe.New("ex2", 2, []string{path2}, map[string]fe.NamesErr{path2: {Names: []string{name2}, Err: nil}}),
			},
			wantInv: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      name1,
					Locations: []string{path1},
					Extractor: "ex1",
				},
				&extractor.Inventory{
					Name:      name2,
					Locations: []string{path2},
					Extractor: "ex2",
				},
			},
			wantStatus: []*plugin.Status{
				&plugin.Status{Name: "ex1", Version: 1, Status: success},
				&plugin.Status{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Dir skipped",
			ex: []extractor.InventoryExtractor{
				fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: []string{name1}, Err: nil}}),
				fe.New("ex2", 2, []string{path2}, map[string]fe.NamesErr{path2: {Names: []string{name2}, Err: nil}}),
			},
			dirsToSkip: []string{"dir1"},
			wantInv: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      name2,
					Locations: []string{path2},
					Extractor: "ex2",
				},
			},
			wantStatus: []*plugin.Status{
				&plugin.Status{Name: "ex1", Version: 1, Status: success},
				&plugin.Status{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 5,
		},
		{
			desc: "Dir skipped with absolute path",
			ex: []extractor.InventoryExtractor{
				fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: []string{name1}, Err: nil}}),
				fe.New("ex2", 2, []string{path2}, map[string]fe.NamesErr{path2: {Names: []string{name2}, Err: nil}}),
			},
			// ScanRoot is CWD
			dirsToSkip: []string{path.Join(cwd, "dir1")},
			wantInv: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      name2,
					Locations: []string{path2},
					Extractor: "ex2",
				},
			},
			wantStatus: []*plugin.Status{
				&plugin.Status{Name: "ex1", Version: 1, Status: success},
				&plugin.Status{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 5,
		},
		{
			desc: "Dir skipped not relative to ScanRoot",
			ex: []extractor.InventoryExtractor{
				fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: []string{name1}, Err: nil}}),
				fe.New("ex2", 2, []string{path2}, map[string]fe.NamesErr{path2: {Names: []string{name2}, Err: nil}}),
			},
			// ScanRoot is CWD, dirsToSkip is in its parent dir.
			dirsToSkip: []string{path.Join(filepath.Dir(cwd), "dir1")},
			wantErr:    cmpopts.AnyError,
		},
		{
			desc: "Dir skipped using regex",
			ex: []extractor.InventoryExtractor{
				fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: []string{name1}, Err: nil}}),
				fe.New("ex2", 2, []string{path2}, map[string]fe.NamesErr{path2: {Names: []string{name2}, Err: nil}}),
			},
			skipDirRegex: ".*1",
			wantInv: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      name2,
					Locations: []string{path2},
					Extractor: "ex2",
				},
			},
			wantStatus: []*plugin.Status{
				&plugin.Status{Name: "ex1", Version: 1, Status: success},
				&plugin.Status{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 5,
		},
		{
			desc: "Dir skipped with full match of dirname",
			ex: []extractor.InventoryExtractor{
				fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: []string{name1}, Err: nil}}),
				fe.New("ex2", 2, []string{path2}, map[string]fe.NamesErr{path2: {Names: []string{name2}, Err: nil}}),
			},
			skipDirRegex: "/sub$",
			wantInv: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      name1,
					Locations: []string{path1},
					Extractor: "ex1",
				},
			},
			wantStatus: []*plugin.Status{
				&plugin.Status{Name: "ex1", Version: 1, Status: success},
				&plugin.Status{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 5,
		},
		{
			desc: "skip regex set but not match",
			ex: []extractor.InventoryExtractor{
				fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: []string{name1}, Err: nil}}),
				fe.New("ex2", 2, []string{path2}, map[string]fe.NamesErr{path2: {Names: []string{name2}, Err: nil}}),
			},
			skipDirRegex: "asdf",
			wantInv: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      name1,
					Locations: []string{path1},
					Extractor: "ex1",
				},
				&extractor.Inventory{
					Name:      name2,
					Locations: []string{path2},
					Extractor: "ex2",
				},
			},
			wantStatus: []*plugin.Status{
				&plugin.Status{Name: "ex1", Version: 1, Status: success},
				&plugin.Status{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Duplicate inventory results kept separate",
			ex: []extractor.InventoryExtractor{
				fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: []string{name1}, Err: nil}}),
				fe.New("ex2", 2, []string{path2}, map[string]fe.NamesErr{path2: {Names: []string{name1}, Err: nil}}),
			},
			wantInv: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      name1,
					Locations: []string{path1},
					Extractor: "ex1",
				},
				&extractor.Inventory{
					Name:      name1,
					Locations: []string{path2},
					Extractor: "ex2",
				},
			},
			wantStatus: []*plugin.Status{
				&plugin.Status{Name: "ex1", Version: 1, Status: success},
				&plugin.Status{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc: "nil result",
			ex: []extractor.InventoryExtractor{
				// An Extractor that returns nil.
				fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {nil, nil}}),
			},
			wantInv: []*extractor.Inventory{},
			wantStatus: []*plugin.Status{
				&plugin.Status{Name: "ex1", Version: 1, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Extraction fails with partial results",
			ex: []extractor.InventoryExtractor{
				fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: []string{name1}, Err: errors.New("extraction failed")}}),
			},
			wantInv: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      name1,
					Locations: []string{path1},
					Extractor: "ex1",
				},
			},
			wantStatus: []*plugin.Status{
				&plugin.Status{Name: "ex1", Version: 1, Status: &plugin.ScanStatus{
					Status: plugin.ScanStatusPartiallySucceeded, FailureReason: fmt.Sprintf("%s: extraction failed", path1),
				}},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Extraction fails with no results",
			ex: []extractor.InventoryExtractor{
				fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: nil, Err: errors.New("extraction failed")}}),
			},
			wantInv: []*extractor.Inventory{},
			wantStatus: []*plugin.Status{
				&plugin.Status{Name: "ex1", Version: 1, Status: &plugin.ScanStatus{
					Status: plugin.ScanStatusFailed, FailureReason: fmt.Sprintf("%s: extraction failed", path1),
				}},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Extraction fails several times",
			ex: []extractor.InventoryExtractor{
				fe.New("ex1", 1, []string{path1, path2}, map[string]fe.NamesErr{
					path1: {Names: nil, Err: errors.New("extraction failed")},
					path2: {Names: nil, Err: errors.New("extraction failed")},
				}),
			},
			wantInv: []*extractor.Inventory{},
			wantStatus: []*plugin.Status{
				&plugin.Status{Name: "ex1", Version: 1, Status: &plugin.ScanStatus{
					Status:        plugin.ScanStatusFailed,
					FailureReason: fmt.Sprintf("%s: extraction failed\n%s: extraction failed", path1, path2),
				}},
			},
			wantInodeCount: 6,
		},
		{
			desc: "More inodes visited than limit, Error",
			ex: []extractor.InventoryExtractor{
				fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: []string{name1}, Err: nil}}),
				fe.New("ex2", 2, []string{path2}, map[string]fe.NamesErr{path2: {Names: []string{name2}, Err: nil}}),
			},
			maxInodes: 2,
			wantInv:   []*extractor.Inventory{},
			wantStatus: []*plugin.Status{
				&plugin.Status{Name: "ex1", Version: 1, Status: success},
				&plugin.Status{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 2,
			wantErr:        cmpopts.AnyError,
		},
		{
			desc: "Less inodes visited than limit, no Error",
			ex: []extractor.InventoryExtractor{
				fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: []string{name1}, Err: nil}}),
				fe.New("ex2", 2, []string{path2}, map[string]fe.NamesErr{path2: {Names: []string{name2}, Err: nil}}),
			},
			maxInodes: 6,
			wantInv: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      name1,
					Locations: []string{path1},
					Extractor: "ex1",
				},
				&extractor.Inventory{
					Name:      name2,
					Locations: []string{path2},
					Extractor: "ex2",
				},
			},
			wantStatus: []*plugin.Status{
				&plugin.Status{Name: "ex1", Version: 1, Status: success},
				&plugin.Status{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 6,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			fc := &fakeCollector{}
			var skipDirRegex *regexp.Regexp
			if tc.skipDirRegex != "" {
				skipDirRegex = regexp.MustCompile(tc.skipDirRegex)
			}
			config := &extractor.Config{
				Extractors:   tc.ex,
				DirsToSkip:   tc.dirsToSkip,
				SkipDirRegex: skipDirRegex,
				MaxInodes:    tc.maxInodes,
				ScanRoot:     ".",
				FS:           fsys,
				Stats:        fc,
			}
			gotInv, gotStatus, err := extractor.RunFS(context.Background(), config)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("extractor.Run(%v) error got diff (-want +got):\n%s", tc.ex, diff)
			}

			if fc.AfterInodeVisitedCount != tc.wantInodeCount {
				t.Errorf("extractor.Run(%v) inodes visisted: got %d, want %d", tc.ex, fc.AfterInodeVisitedCount, tc.wantInodeCount)
			}

			// The order of the locations doesn't matter.
			for _, i := range gotInv {
				sort.Strings(i.Locations)
			}

			if diff := cmp.Diff(tc.wantInv, gotInv, cmpopts.SortSlices(invLess)); diff != "" {
				t.Errorf("extractor.Run(%v): unexpected findings (-want +got):\n%s", tc.ex, diff)
			}

			sortStatus := func(s1, s2 *plugin.Status) bool {
				return s1.Name < s2.Name
			}
			if diff := cmp.Diff(tc.wantStatus, gotStatus, cmpopts.SortSlices(sortStatus)); diff != "" {
				t.Errorf("extractor.Run(%v): unexpected status (-want +got):\n%s", tc.ex, diff)
			}
		})
	}
}

// To not break the test every time we add a new metric, we inherit from the NoopCollector.
type fakeCollector struct {
	stats.NoopCollector
	AfterInodeVisitedCount int
}

func (c *fakeCollector) AfterInodeVisited(path string) { c.AfterInodeVisitedCount++ }

func invLess(i1, i2 *extractor.Inventory) bool {
	if i1.Name != i2.Name {
		return i1.Name < i2.Name
	}
	return false
}

// A fake implementation of fs.FS with a single file under root which errors when its opened.
type fakeFS struct{}

func (fakeFS) Open(name string) (fs.File, error) {
	if name == "." {
		return &fakeDir{dirs: []fs.DirEntry{&fakeDirEntry{}}}, nil
	}
	return nil, errors.New("failed to open")
}
func (fakeFS) Stat(name string) (fs.FileInfo, error) {
	return &fakeFileInfo{dir: true}, nil
}

type fakeDir struct {
	dirs []fs.DirEntry
}

func (fakeDir) Stat() (fs.FileInfo, error) { return &fakeFileInfo{dir: true}, nil }
func (fakeDir) Read([]byte) (int, error)   { return 0, errors.New("failed to read") }
func (fakeDir) Close() error               { return nil }
func (f *fakeDir) ReadDir(n int) ([]fs.DirEntry, error) {
	if n <= 0 {
		t := f.dirs
		f.dirs = []fs.DirEntry{}
		return t, nil
	}
	if len(f.dirs) == 0 {
		return f.dirs, io.EOF
	}
	n = min(n, len(f.dirs))
	t := f.dirs[:n]
	f.dirs = f.dirs[n:]
	return t, nil
}

type fakeFileInfo struct{ dir bool }

func (fakeFileInfo) Name() string { return "/" }
func (fakeFileInfo) Size() int64  { return 1 }
func (i *fakeFileInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir + 0777
	}
	return 0777
}
func (fakeFileInfo) ModTime() time.Time { return time.Now() }
func (i *fakeFileInfo) IsDir() bool     { return i.dir }
func (fakeFileInfo) Sys() any           { return nil }

type fakeDirEntry struct{}

func (fakeDirEntry) Name() string               { return "file" }
func (fakeDirEntry) IsDir() bool                { return false }
func (fakeDirEntry) Type() fs.FileMode          { return 0777 }
func (fakeDirEntry) Info() (fs.FileInfo, error) { return &fakeFileInfo{dir: false}, nil }

func TestRun_ReadError(t *testing.T) {
	ex := []extractor.InventoryExtractor{
		fe.New("ex1", 1, []string{"file"},
			map[string]fe.NamesErr{"file": {Names: []string{"software"}, Err: nil}}),
	}
	wantStatus := []*plugin.Status{
		&plugin.Status{Name: "ex1", Version: 1, Status: &plugin.ScanStatus{
			Status: plugin.ScanStatusFailed, FailureReason: "Open(file): failed to open",
		}},
	}
	config := &extractor.Config{
		Extractors: ex,
		DirsToSkip: []string{},
		ScanRoot:   ".",
		FS:         &fakeFS{},
		Stats:      stats.NoopCollector{},
	}
	gotInv, gotStatus, err := extractor.RunFS(context.Background(), config)
	if err != nil {
		t.Fatalf("extractor.Run(%v): %v", ex, err)
	}

	if len(gotInv) > 0 {
		t.Errorf("extractor.Run(%v): expected empty inventory, got %v", ex, gotInv)
	}

	if diff := cmp.Diff(wantStatus, gotStatus); diff != "" {
		t.Errorf("extractor.Run(%v): unexpected status (-want +got):\n%s", ex, diff)
	}
}
