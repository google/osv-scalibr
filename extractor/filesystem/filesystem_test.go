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

package filesystem_test

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"testing"
	"testing/fstest"
	"time"

	"github.com/gobwas/glob"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"
	fe "github.com/google/osv-scalibr/testing/fakeextractor"
	"github.com/google/osv-scalibr/testing/fakefs"
)

// pathsMapFS provides a hooked version of MapFS that forces slashes. Because depending on the
// tested system, the path might contain backslashes instead but mapfs doesn't support them.
type pathsMapFS struct {
	mapfs fstest.MapFS
}

func (fsys pathsMapFS) Open(name string) (fs.File, error) {
	name = filepath.ToSlash(name)
	return fsys.mapfs.Open(name)
}
func (fsys pathsMapFS) ReadDir(name string) ([]fs.DirEntry, error) {
	name = filepath.ToSlash(name)
	return fsys.mapfs.ReadDir(name)
}
func (fsys pathsMapFS) Stat(name string) (fs.FileInfo, error) {
	name = filepath.ToSlash(name)
	return fsys.mapfs.Stat(name)
}

func TestInitWalkContext(t *testing.T) {
	dummyFS := scalibrfs.DirFS(".")
	testCases := []struct {
		desc           string
		scanRoots      map[string][]string
		filesToExtract map[string][]string
		dirsToSkip     map[string][]string
		wantErr        error
	}{
		{
			desc: "valid config with filesToExtract raises no error",
			scanRoots: map[string][]string{
				"darwin":  {"/scanroot/"},
				"linux":   {"/scanroot/"},
				"windows": {"C:\\scanroot\\"},
			},
			filesToExtract: map[string][]string{
				"darwin":  {"/scanroot/file1.txt", "/scanroot/file2.txt"},
				"linux":   {"/scanroot/file1.txt", "/scanroot/file2.txt"},
				"windows": {"C:\\scanroot\\file1.txt", "C:\\scanroot\\file2.txt"},
			},
			wantErr: nil,
		},
		{
			desc: "valid config with dirsToSkip raises no error",
			scanRoots: map[string][]string{
				"darwin":  {"/scanroot/", "/someotherroot/"},
				"linux":   {"/scanroot/", "/someotherroot/"},
				"windows": {"C:\\scanroot\\", "D:\\someotherroot\\"},
			},
			dirsToSkip: map[string][]string{
				"darwin":  {"/scanroot/mydir/", "/someotherroot/mydir/"},
				"linux":   {"/scanroot/mydir/", "/someotherroot/mydir/"},
				"windows": {"C:\\scanroot\\mydir\\", "D:\\someotherroot\\mydir\\"},
			},
			wantErr: nil,
		},
		{
			desc: "filesToExtract not relative to any root raises error",
			scanRoots: map[string][]string{
				"darwin":  {"/scanroot/"},
				"linux":   {"/scanroot/"},
				"windows": {"C:\\scanroot\\"},
			},
			filesToExtract: map[string][]string{
				"darwin":  {"/scanroot/myfile.txt", "/myotherroot/file1.txt"},
				"linux":   {"/scanroot/myfile.txt", "/myotherroot/file1.txt"},
				"windows": {"C:\\scanroot\\myfile.txt", "D:\\myotherroot\\file1.txt"},
			},
			wantErr: filesystem.ErrNotRelativeToScanRoots,
		},
		{
			desc: "dirsToSkip not relative to any root raises error",
			scanRoots: map[string][]string{
				"darwin":  {"/scanroot/"},
				"linux":   {"/scanroot/"},
				"windows": {"C:\\scanroot\\"},
			},
			dirsToSkip: map[string][]string{
				"darwin":  {"/scanroot/mydir/", "/myotherroot/mydir/"},
				"linux":   {"/scanroot/mydir/", "/myotherroot/mydir/"},
				"windows": {"C:\\scanroot\\mydir\\", "D:\\myotherroot\\mydir\\"},
			},
			wantErr: filesystem.ErrNotRelativeToScanRoots,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			os := runtime.GOOS
			if _, ok := tc.scanRoots[os]; !ok {
				t.Fatalf("system %q not defined in test, please extend the tests", os)
			}
			config := &filesystem.Config{
				FilesToExtract: tc.filesToExtract[os],
				DirsToSkip:     tc.dirsToSkip[os],
			}
			scanRoots := []*scalibrfs.ScanRoot{}
			for _, p := range tc.scanRoots[os] {
				scanRoots = append(scanRoots, &scalibrfs.ScanRoot{FS: dummyFS, Path: p})
			}
			_, err := filesystem.InitWalkContext(
				t.Context(), config, scanRoots,
			)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("filesystem.InitializeWalkContext(%v) error got diff (-want +got):\n%s", config, diff)
			}
		})
	}
}

func TestRunFS(t *testing.T) {
	success := &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}
	path1 := "dir1/file1.txt"
	path2 := "dir2/sub/file2.txt"
	fsys := pathsMapFS{
		mapfs: fstest.MapFS{
			".":                  {Mode: fs.ModeDir},
			"dir1":               {Mode: fs.ModeDir},
			"dir2":               {Mode: fs.ModeDir},
			"dir1/file1.txt":     {Data: []byte("Content 1")},
			"dir2/sub/file2.txt": {Data: []byte("Content 2")},
		},
	}
	name1 := "software1"
	name2 := "software2"

	fakeEx1 := fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: []string{name1}, Err: nil}})
	fakeEx2 := fe.New("ex2", 2, []string{path2}, map[string]fe.NamesErr{path2: {Names: []string{name2}, Err: nil}})
	fakeEx2WithInv1 := fe.New("ex2", 2, []string{path2}, map[string]fe.NamesErr{path2: {Names: []string{name1}, Err: nil}})
	fakeExWithPartialResult := fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: []string{name1}, Err: errors.New("extraction failed")}})

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd(): %v", err)
	}

	testCases := []struct {
		desc           string
		ex             []filesystem.Extractor
		filesToExtract []string
		dirsToSkip     []string
		skipDirGlob    string
		skipDirRegex   string
		storeAbsPath   bool
		maxInodes      int
		wantErr        error
		wantInv        []*extractor.Inventory
		wantStatus     []*plugin.Status
		wantInodeCount int
	}{
		{
			desc: "Extractors successful",
			ex:   []filesystem.Extractor{fakeEx1, fakeEx2},
			wantInv: []*extractor.Inventory{
				{
					Name:      name1,
					Locations: []string{path1},
					Extractor: fakeEx1,
				},
				{
					Name:      name2,
					Locations: []string{path2},
					Extractor: fakeEx2,
				},
			},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Dir skipped",
			ex:   []filesystem.Extractor{fakeEx1, fakeEx2},
			// ScanRoot is CWD
			dirsToSkip: []string{path.Join(cwd, "dir1")},
			wantInv: []*extractor.Inventory{
				{
					Name:      name2,
					Locations: []string{path2},
					Extractor: fakeEx2,
				},
			},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 5,
		},
		{
			desc:       "Dir skipped with absolute path",
			ex:         []filesystem.Extractor{fakeEx1, fakeEx2},
			dirsToSkip: []string{"dir1"},
			wantInv: []*extractor.Inventory{
				{
					Name:      name2,
					Locations: []string{path2},
					Extractor: fakeEx2,
				},
			},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 5,
		},
		{
			desc:         "Dir skipped using regex",
			ex:           []filesystem.Extractor{fakeEx1, fakeEx2},
			skipDirRegex: ".*1",
			wantInv: []*extractor.Inventory{
				{
					Name:      name2,
					Locations: []string{path2},
					Extractor: fakeEx2,
				},
			},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 5,
		},
		{
			desc:         "Dir skipped with full match of dirname",
			ex:           []filesystem.Extractor{fakeEx1, fakeEx2},
			skipDirRegex: "/sub$",
			wantInv: []*extractor.Inventory{
				{
					Name:      name1,
					Locations: []string{path1},
					Extractor: fakeEx1,
				},
			},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 5,
		},
		{
			desc:         "skip regex set but not match",
			ex:           []filesystem.Extractor{fakeEx1, fakeEx2},
			skipDirRegex: "asdf",
			wantInv: []*extractor.Inventory{
				{
					Name:      name1,
					Locations: []string{path1},
					Extractor: fakeEx1,
				},
				{
					Name:      name2,
					Locations: []string{path2},
					Extractor: fakeEx2,
				},
			},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc:        "Dirs skipped using glob",
			ex:          []filesystem.Extractor{fakeEx1, fakeEx2},
			skipDirGlob: "dir*",
			wantInv:     []*extractor.Inventory{},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 3,
		},
		{
			desc:        "Subdirectory skipped using glob",
			ex:          []filesystem.Extractor{fakeEx1, fakeEx2},
			skipDirGlob: "**/sub",
			wantInv: []*extractor.Inventory{
				{
					Name:      name1,
					Locations: []string{path1},
					Extractor: fakeEx1,
				},
			},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 5,
		},
		{
			desc:        "Dirs skipped using glob pattern lists",
			ex:          []filesystem.Extractor{fakeEx1, fakeEx2},
			skipDirGlob: "{dir1,dir2}",
			wantInv:     []*extractor.Inventory{},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 3,
		},
		{
			desc:        "No directories matched using glob",
			ex:          []filesystem.Extractor{fakeEx1, fakeEx2},
			skipDirGlob: "none",
			wantInv: []*extractor.Inventory{
				{
					Name:      name1,
					Locations: []string{path1},
					Extractor: fakeEx1,
				},
				{
					Name:      name2,
					Locations: []string{path2},
					Extractor: fakeEx2,
				},
			},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Duplicate inventory results kept separate",
			ex:   []filesystem.Extractor{fakeEx1, fakeEx2WithInv1},
			wantInv: []*extractor.Inventory{
				{
					Name:      name1,
					Locations: []string{path1},
					Extractor: fakeEx1,
				},
				{
					Name:      name1,
					Locations: []string{path2},
					Extractor: fakeEx2WithInv1,
				},
			},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Extract specific file",
			ex:   []filesystem.Extractor{fakeEx1, fakeEx2},
			// ScanRoot is CWD
			filesToExtract: []string{path.Join(cwd, path2)},
			wantInv: []*extractor.Inventory{
				{
					Name:      name2,
					Locations: []string{path2},
					Extractor: fakeEx2,
				},
			},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 1,
		},
		{
			desc:           "Extract specific file with absolute path",
			ex:             []filesystem.Extractor{fakeEx1, fakeEx2},
			filesToExtract: []string{path2},
			wantInv: []*extractor.Inventory{
				{
					Name:      name2,
					Locations: []string{path2},
					Extractor: fakeEx2,
				},
			},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 1,
		},
		{
			desc: "nil result",
			ex: []filesystem.Extractor{
				// An Extractor that returns nil.
				fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {nil, nil}}),
			},
			wantInv: []*extractor.Inventory{},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Extraction fails with partial results",
			ex:   []filesystem.Extractor{fakeExWithPartialResult},
			wantInv: []*extractor.Inventory{
				{
					Name:      name1,
					Locations: []string{path1},
					Extractor: fakeExWithPartialResult,
				},
			},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: &plugin.ScanStatus{
					Status: plugin.ScanStatusPartiallySucceeded, FailureReason: fmt.Sprintf("%s: extraction failed", path1),
				}},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Extraction fails with no results",
			ex: []filesystem.Extractor{
				fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: nil, Err: errors.New("extraction failed")}}),
			},
			wantInv: []*extractor.Inventory{},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: &plugin.ScanStatus{
					Status: plugin.ScanStatusFailed, FailureReason: fmt.Sprintf("%s: extraction failed", path1),
				}},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Extraction fails several times",
			ex: []filesystem.Extractor{
				fe.New("ex1", 1, []string{path1, path2}, map[string]fe.NamesErr{
					path1: {Names: nil, Err: errors.New("extraction failed")},
					path2: {Names: nil, Err: errors.New("extraction failed")},
				}),
			},
			wantInv: []*extractor.Inventory{},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: &plugin.ScanStatus{
					Status:        plugin.ScanStatusFailed,
					FailureReason: fmt.Sprintf("%s: extraction failed\n%s: extraction failed", path1, path2),
				}},
			},
			wantInodeCount: 6,
		},
		{
			desc:      "More inodes visited than limit, Error",
			ex:        []filesystem.Extractor{fakeEx1, fakeEx2},
			maxInodes: 2,
			wantInv:   []*extractor.Inventory{},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 2,
			wantErr:        cmpopts.AnyError,
		},
		{
			desc:      "Less inodes visited than limit, no Error",
			ex:        []filesystem.Extractor{fakeEx1, fakeEx2},
			maxInodes: 6,
			wantInv: []*extractor.Inventory{
				{
					Name:      name1,
					Locations: []string{path1},
					Extractor: fakeEx1,
				},
				{
					Name:      name2,
					Locations: []string{path2},
					Extractor: fakeEx2,
				},
			},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Extractors successful store absolute path when requested",
			ex:   []filesystem.Extractor{fakeEx1, fakeEx2},
			wantInv: []*extractor.Inventory{
				{
					Name:      name1,
					Locations: []string{filepath.Join(cwd, path1)},
					Extractor: fakeEx1,
				},
				{
					Name:      name2,
					Locations: []string{filepath.Join(cwd, path2)},
					Extractor: fakeEx2,
				},
			},
			storeAbsPath: true,
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 6,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			fc := &fakeCollector{}
			var skipDirRegex *regexp.Regexp
			var skipDirGlob glob.Glob
			if tc.skipDirRegex != "" {
				skipDirRegex = regexp.MustCompile(tc.skipDirRegex)
			}
			if tc.skipDirGlob != "" {
				skipDirGlob = glob.MustCompile(tc.skipDirGlob)
			}
			config := &filesystem.Config{
				Extractors:     tc.ex,
				FilesToExtract: tc.filesToExtract,
				DirsToSkip:     tc.dirsToSkip,
				SkipDirRegex:   skipDirRegex,
				SkipDirGlob:    skipDirGlob,
				MaxInodes:      tc.maxInodes,
				ScanRoots: []*scalibrfs.ScanRoot{{
					FS: fsys, Path: ".",
				}},
				Stats:             fc,
				StoreAbsolutePath: tc.storeAbsPath,
			}
			wc, err := filesystem.InitWalkContext(
				t.Context(), config, []*scalibrfs.ScanRoot{{
					FS: fsys, Path: cwd,
				}},
			)
			if err != nil {
				t.Fatalf("filesystem.InitializeWalkContext(..., %v): %v", fsys, err)
			}
			if err = wc.UpdateScanRoot(cwd, fsys); err != nil {
				t.Fatalf("wc.UpdateScanRoot(..., %v): %v", fsys, err)
			}
			gotInv, gotStatus, err := filesystem.RunFS(t.Context(), config, wc)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("extractor.Run(%v) error got diff (-want +got):\n%s", tc.ex, diff)
			}

			if fc.AfterInodeVisitedCount != tc.wantInodeCount {
				t.Errorf("extractor.Run(%v) inodes visited: got %d, want %d", tc.ex, fc.AfterInodeVisitedCount, tc.wantInodeCount)
			}

			// The order of the locations doesn't matter.
			for _, i := range gotInv {
				sort.Strings(i.Locations)
			}

			if diff := cmp.Diff(tc.wantInv, gotInv, cmpopts.SortSlices(invLess), fe.AllowUnexported, cmpopts.EquateErrors()); diff != "" {
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
func (fakeFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return nil, errors.New("not implemented")
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

func TestRunFS_ReadError(t *testing.T) {
	ex := []filesystem.Extractor{
		fe.New("ex1", 1, []string{"file"},
			map[string]fe.NamesErr{"file": {Names: []string{"software"}, Err: nil}}),
	}
	wantStatus := []*plugin.Status{
		{Name: "ex1", Version: 1, Status: &plugin.ScanStatus{
			Status: plugin.ScanStatusFailed, FailureReason: "Open(file): failed to open",
		}},
	}
	fsys := &fakeFS{}
	config := &filesystem.Config{
		Extractors: ex,
		DirsToSkip: []string{},
		ScanRoots: []*scalibrfs.ScanRoot{{
			FS: fsys, Path: ".",
		}},
		Stats: stats.NoopCollector{},
	}
	wc, err := filesystem.InitWalkContext(t.Context(), config, config.ScanRoots)
	if err != nil {
		t.Fatalf("filesystem.InitializeWalkContext(%v): %v", config, err)
	}
	if err := wc.UpdateScanRoot(".", fsys); err != nil {
		t.Fatalf("wc.UpdateScanRoot(%v): %v", config, err)
	}
	gotInv, gotStatus, err := filesystem.RunFS(t.Context(), config, wc)
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

type fakeFileAPI struct {
	path string
	info fakefs.FakeFileInfo
}

func (f fakeFileAPI) Path() string { return f.path }
func (f fakeFileAPI) Stat() (fs.FileInfo, error) {
	return f.info, nil
}

func TestIsInterestingExecutable(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		mode        fs.FileMode
		want        bool
		wantWindows bool
	}{
		{
			name: "user executable",
			path: "some/path/a",
			mode: 0766,
			want: true,
		},
		{
			name: "group executable",
			path: "some/path/a",
			mode: 0676,
			want: true,
		},
		{
			name: "other executable",
			path: "some/path/a",
			mode: 0667,
			want: true,
		},
		{
			name: "windows exe",
			path: "some/path/a.exe",
			mode: 0666,
			want: true,
		},
		{
			name: "windows dll",
			path: "some/path/a.dll",
			mode: 0666,
			want: true,
		},
		{
			name:        "not executable bit set",
			path:        "some/path/a",
			mode:        0640,
			want:        false,
			wantWindows: true,
		},
		{
			name: "executable required",
			path: "some/path/a",
			mode: 0766,
			want: true,
		},
		{
			name: "unwanted extension",
			path: "some/path/a.html",
			mode: 0766,
			want: false,
		},
		{
			name: "another unwanted extension",
			path: "some/path/a.txt",
			mode: 0766,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filesystem.IsInterestingExecutable(fakeFileAPI{tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: tt.mode,
			}})

			want := tt.want
			// For Windows we don't check the executable bit on files.
			if runtime.GOOS == "windows" && !want {
				want = tt.wantWindows
			}

			if got != want {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, want)
			}
		})
	}
}
