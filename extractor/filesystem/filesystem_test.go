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
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/gobwas/glob"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/extracttest"
	fe "github.com/google/osv-scalibr/testing/fakeextractor"
	"github.com/google/osv-scalibr/testing/fakefs"
)

// Map of file paths to contents. Empty contents denote directories.
type mapFS map[string][]byte

func TestInitWalkContext(t *testing.T) {
	dummyFS := scalibrfs.DirFS(".")
	testCases := []struct {
		desc           string
		scanRoots      map[string][]string
		pathsToExtract map[string][]string
		dirsToSkip     map[string][]string
		wantErr        error
	}{
		{
			desc: "valid config with pathsToExtract raises no error",
			scanRoots: map[string][]string{
				"darwin":  {"/scanroot/"},
				"linux":   {"/scanroot/"},
				"windows": {"C:\\scanroot\\"},
			},
			pathsToExtract: map[string][]string{
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
			desc: "pathsToExtract not relative to any root raises error",
			scanRoots: map[string][]string{
				"darwin":  {"/scanroot/"},
				"linux":   {"/scanroot/"},
				"windows": {"C:\\scanroot\\"},
			},
			pathsToExtract: map[string][]string{
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
				PathsToExtract: tc.pathsToExtract[os],
				DirsToSkip:     tc.dirsToSkip[os],
			}
			scanRoots := []*scalibrfs.ScanRoot{}
			for _, p := range tc.scanRoots[os] {
				scanRoots = append(scanRoots, &scalibrfs.ScanRoot{FS: dummyFS, Path: p})
			}
			_, err := filesystem.InitWalkContext(
				context.Background(), config, scanRoots,
			)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("filesystem.InitializeWalkContext(%v) error got diff (-want +got):\n%s", config, diff)
			}
		})
	}
}

// A fake extractor that only extracts directories.
type fakeExtractorDirs struct {
	dir  string
	name string
}

func (fakeExtractorDirs) Name() string { return "ex-dirs" }
func (fakeExtractorDirs) Version() int { return 1 }
func (fakeExtractorDirs) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{ExtractFromDirs: true}
}
func (e fakeExtractorDirs) FileRequired(api filesystem.FileAPI) bool {
	return api.Path() == e.dir
}
func (e fakeExtractorDirs) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	path := filepath.ToSlash(input.Path)
	if path == e.dir {
		return inventory.Inventory{Packages: []*extractor.Package{&extractor.Package{
			Name:      e.name,
			Locations: []string{path},
		}}}, nil
	}
	return inventory.Inventory{}, errors.New("unrecognized path")
}

func TestRunFS(t *testing.T) {
	success := &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}
	dir1 := "dir1"
	path1 := "dir1/file1.txt"
	path2 := "dir2/sub/file2.txt"
	fsys := setupMapFS(t, mapFS{
		".":                  nil,
		"dir1":               nil,
		"dir2":               nil,
		"dir1/file1.txt":     []byte("Content"),
		"dir2/sub/file2.txt": []byte("More content"),
	})
	name1 := "software1"
	name2 := "software2"

	fakeEx1 := fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: []string{name1}, Err: nil}})
	fakeEx2 := fe.New("ex2", 2, []string{path2}, map[string]fe.NamesErr{path2: {Names: []string{name2}, Err: nil}})
	fakeEx2WithPKG1 := fe.New("ex2", 2, []string{path2}, map[string]fe.NamesErr{path2: {Names: []string{name1}, Err: nil}})
	fakeExWithPartialResult := fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: []string{name1}, Err: errors.New("extraction failed")}})
	fakeExDirs := &fakeExtractorDirs{dir: dir1, name: name2}
	fakeExDirsRequiresFile := &fakeExtractorDirs{dir: path1, name: name2}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd(): %v", err)
	}

	testCases := []struct {
		desc             string
		ex               []filesystem.Extractor
		pathsToExtract   []string
		ignoreSubDirs    bool
		dirsToSkip       []string
		skipDirGlob      string
		skipDirRegex     string
		storeAbsPath     bool
		maxInodes        int
		maxFileSizeBytes int
		wantErr          error
		wantPkg          inventory.Inventory
		wantStatus       []*plugin.Status
		wantInodeCount   int
	}{
		{
			desc: "Extractors successful",
			ex:   []filesystem.Extractor{fakeEx1, fakeEx2},
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:      name1,
					Locations: []string{path1},
					Plugins:   []string{fakeEx1.Name()},
				},
				{
					Name:      name2,
					Locations: []string{path2},
					Plugins:   []string{fakeEx2.Name()},
				},
			}},
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
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:      name2,
					Locations: []string{path2},
					Plugins:   []string{fakeEx2.Name()},
				},
			}},
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
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:      name2,
					Locations: []string{path2},
					Plugins:   []string{fakeEx2.Name()},
				},
			}},
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
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:      name2,
					Locations: []string{path2},
					Plugins:   []string{fakeEx2.Name()},
				},
			}},
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
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:      name1,
					Locations: []string{path1},
					Plugins:   []string{fakeEx1.Name()},
				},
			}},
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
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:      name1,
					Locations: []string{path1},
					Plugins:   []string{fakeEx1.Name()},
				},
				{
					Name:      name2,
					Locations: []string{path2},
					Plugins:   []string{fakeEx2.Name()},
				},
			}},
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
			wantPkg:     inventory.Inventory{},
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
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:      name1,
					Locations: []string{path1},
					Plugins:   []string{fakeEx1.Name()},
				},
			}},
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
			wantPkg:     inventory.Inventory{},
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
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:      name1,
					Locations: []string{path1},
					Plugins:   []string{fakeEx1.Name()},
				},
				{
					Name:      name2,
					Locations: []string{path2},
					Plugins:   []string{fakeEx2.Name()},
				},
			}},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Duplicate inventory results kept separate",
			ex:   []filesystem.Extractor{fakeEx1, fakeEx2WithPKG1},
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:      name1,
					Locations: []string{path1},
					Plugins:   []string{fakeEx1.Name()},
				},
				{
					Name:      name1,
					Locations: []string{path2},
					Plugins:   []string{fakeEx2WithPKG1.Name()},
				},
			}},
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
			pathsToExtract: []string{path.Join(cwd, path2)},
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:      name2,
					Locations: []string{path2},
					Plugins:   []string{fakeEx2.Name()},
				},
			}},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 1,
		},
		{
			desc:           "Extract specific file with absolute path",
			ex:             []filesystem.Extractor{fakeEx1, fakeEx2},
			pathsToExtract: []string{path2},
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:      name2,
					Locations: []string{path2},
					Plugins:   []string{fakeEx2.Name()},
				},
			}},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 1,
		},
		{
			desc:           "Extract directory contents",
			ex:             []filesystem.Extractor{fakeEx1, fakeEx2},
			pathsToExtract: []string{"dir2"},
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:      name2,
					Locations: []string{path2},
					Plugins:   []string{fakeEx2.Name()},
				},
			}},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 3,
		},
		{
			desc:           "Point to nonexistent file",
			ex:             []filesystem.Extractor{fakeEx1, fakeEx2},
			pathsToExtract: []string{"nonexistent"},
			wantPkg:        inventory.Inventory{},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 1,
		},
		{
			desc:           "Skip sub-dirs: Inventory found in root dir",
			ex:             []filesystem.Extractor{fakeEx1, fakeEx2},
			pathsToExtract: []string{"dir1"},
			ignoreSubDirs:  true,
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:      name1,
					Locations: []string{path1},
					Plugins:   []string{fakeEx1.Name()},
				},
			}},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 2,
		},
		{
			desc:           "Skip sub-dirs: Inventory not found in root dir",
			ex:             []filesystem.Extractor{fakeEx1, fakeEx2},
			pathsToExtract: []string{"dir2"},
			ignoreSubDirs:  true,
			wantPkg:        inventory.Inventory{},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 2,
		},
		{
			desc: "nil result",
			ex: []filesystem.Extractor{
				// An Extractor that returns nil.
				fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: nil, Err: nil}}),
			},
			wantPkg: inventory.Inventory{},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Extraction fails with partial results",
			ex:   []filesystem.Extractor{fakeExWithPartialResult},
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:      name1,
					Locations: []string{path1},
					Plugins:   []string{fakeExWithPartialResult.Name()},
				},
			}},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: &plugin.ScanStatus{
					Status: plugin.ScanStatusPartiallySucceeded,
				}},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Extraction fails with no results",
			ex: []filesystem.Extractor{
				fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: nil, Err: errors.New("extraction failed")}}),
			},
			wantPkg: inventory.Inventory{},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: &plugin.ScanStatus{
					Status: plugin.ScanStatusFailed,
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
			wantPkg: inventory.Inventory{},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: &plugin.ScanStatus{
					Status: plugin.ScanStatusFailed,
				}},
			},
			wantInodeCount: 6,
		},
		{
			desc:      "More inodes visited than limit, Error",
			ex:        []filesystem.Extractor{fakeEx1, fakeEx2},
			maxInodes: 2,
			wantPkg:   inventory.Inventory{},
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
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:      name1,
					Locations: []string{path1},
					Plugins:   []string{fakeEx1.Name()},
				},
				{
					Name:      name2,
					Locations: []string{path2},
					Plugins:   []string{fakeEx2.Name()},
				},
			}},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc:             "Large files skipped",
			ex:               []filesystem.Extractor{fakeEx1, fakeEx2},
			maxInodes:        6,
			maxFileSizeBytes: 10,
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:      name1,
					Locations: []string{path1},
					Plugins:   []string{fakeEx1.Name()},
				},
			}},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Extractors successful store absolute path when requested",
			ex:   []filesystem.Extractor{fakeEx1, fakeEx2},
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:      name1,
					Locations: []string{filepath.Join(cwd, path1)},
					Plugins:   []string{fakeEx1.Name()},
				},
				{
					Name:      name2,
					Locations: []string{filepath.Join(cwd, path2)},
					Plugins:   []string{fakeEx2.Name()},
				},
			}},
			storeAbsPath: true,
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Extractor runs on directory",
			ex:   []filesystem.Extractor{fakeEx1, fakeExDirs},
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:      name1,
					Locations: []string{path1},
					Plugins:   []string{fakeEx1.Name()},
				},
				{
					Name:      name2,
					Locations: []string{dir1},
					Plugins:   []string{fakeExDirs.Name()},
				},
			}},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex-dirs", Version: 1, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc:    "Directory Extractor ignores files",
			ex:      []filesystem.Extractor{fakeExDirsRequiresFile},
			wantPkg: inventory.Inventory{Packages: nil},
			wantStatus: []*plugin.Status{
				{Name: "ex-dirs", Version: 1, Status: success},
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
				PathsToExtract: tc.pathsToExtract,
				IgnoreSubDirs:  tc.ignoreSubDirs,
				DirsToSkip:     tc.dirsToSkip,
				SkipDirRegex:   skipDirRegex,
				SkipDirGlob:    skipDirGlob,
				MaxInodes:      tc.maxInodes,
				MaxFileSize:    tc.maxFileSizeBytes,
				ScanRoots: []*scalibrfs.ScanRoot{{
					FS: fsys, Path: ".",
				}},
				Stats:             fc,
				StoreAbsolutePath: tc.storeAbsPath,
			}
			wc, err := filesystem.InitWalkContext(
				context.Background(), config, []*scalibrfs.ScanRoot{{
					FS: fsys, Path: cwd,
				}},
			)
			if err != nil {
				t.Fatalf("filesystem.InitializeWalkContext(..., %v): %v", fsys, err)
			}
			if err = wc.UpdateScanRoot(cwd, fsys); err != nil {
				t.Fatalf("wc.UpdateScanRoot(..., %v): %v", fsys, err)
			}
			gotInv, gotStatus, err := filesystem.RunFS(context.Background(), config, wc)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("extractor.Run(%v) error got diff (-want +got):\n%s", tc.ex, diff)
			}

			if fc.AfterInodeVisitedCount != tc.wantInodeCount {
				t.Errorf("extractor.Run(%v) inodes visited: got %d, want %d", tc.ex, fc.AfterInodeVisitedCount, tc.wantInodeCount)
			}

			// The order of the locations doesn't matter.
			for _, p := range gotInv.Packages {
				sort.Strings(p.Locations)
			}

			if diff := cmp.Diff(tc.wantPkg, gotInv, cmpopts.SortSlices(extracttest.PackageCmpLess), fe.AllowUnexported, cmp.AllowUnexported(fakeExtractorDirs{}), cmpopts.EquateErrors()); diff != "" {
				t.Errorf("extractor.Run(%v): unexpected findings (-want +got):\n%s", tc.ex, diff)
			}

			for _, s := range gotStatus {
				// Failure reason can be non-deterministic depending on the order of
				// files traversed so we're ignoring it.
				s.Status.FailureReason = ""
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

func TestRunFSGitignore(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd(): %v", err)
	}

	name1 := "software1"
	name2 := "software2"
	path1 := "dir1/file1.txt"
	path2 := "dir2/sub/file2.txt"
	fakeEx1 := fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: []string{name1}, Err: nil}})
	fakeEx2 := fe.New("ex2", 2, []string{path2}, map[string]fe.NamesErr{path2: {Names: []string{name2}, Err: nil}})
	ex := []filesystem.Extractor{fakeEx1, fakeEx2}

	testCases := []struct {
		desc           string
		mapFS          mapFS
		pathToExtract  string
		ignoreSubDirs  bool
		wantPkg1       bool
		wantPkg2       bool
		wantInodeCount int
	}{
		{
			desc: "Skip_file",
			mapFS: mapFS{
				".":               nil,
				"dir1":            nil,
				"dir1/file1.txt":  []byte("Content 1"),
				"dir1/.gitignore": []byte("file1.txt"),
			},
			pathToExtract:  "dir1",
			wantPkg1:       false,
			wantInodeCount: 3,
		},
		{
			desc: "Skip_dir",
			mapFS: mapFS{
				".":                  nil,
				"dir2":               nil,
				"dir2/sub":           nil,
				"dir2/sub/file2.txt": []byte("Content 2"),
				"dir2/.gitignore":    []byte("sub"),
			},
			pathToExtract:  "",
			wantPkg2:       false,
			wantInodeCount: 4,
		},
		{
			desc: "Dont_skip_if_no_match",
			mapFS: mapFS{
				".":               nil,
				"dir1":            nil,
				"dir1/file1.txt":  []byte("Content 1"),
				"dir1/.gitignore": []byte("no-match.txt"),
			},
			pathToExtract:  "",
			wantPkg1:       true,
			wantPkg2:       false,
			wantInodeCount: 4,
		},
		{
			desc: "Skip_based_on_parent_gitignore",
			mapFS: mapFS{
				".":                  nil,
				"dir2":               nil,
				"dir2/sub":           nil,
				"dir2/sub/file2.txt": []byte("Content 1"),
				"dir2/.gitignore":    []byte("file2.txt"),
			},
			pathToExtract:  "dir2/sub",
			wantPkg1:       false,
			wantInodeCount: 2,
		},
		{
			desc: "Skip_based_on_child_gitignore",
			mapFS: mapFS{
				".":               nil,
				"dir1":            nil,
				"dir2":            nil,
				"dir2/sub":        nil,
				"dir1/file1.txt":  []byte("Content 1"),
				"dir1/.gitignore": []byte("file1.txt\nfile2.txt"),
				// Not skipped since the skip pattern is in dir1
				"dir2/sub/file2.txt": []byte("Content 2"),
			},
			pathToExtract:  "",
			wantPkg1:       false,
			wantPkg2:       true,
			wantInodeCount: 7,
		},
		{
			desc: "ignore_sub_dirs",
			mapFS: mapFS{
				".":              nil,
				"dir":            nil,
				".gitignore":     []byte("file1.txt"),
				"file1.txt":      []byte("Content 1"),
				"dir/.gitignore": []byte("file1.txt"),
				"dir/file2.txt":  []byte("Content 2"),
			},
			pathToExtract:  "",
			ignoreSubDirs:  true,
			wantPkg1:       false, // Skipped because of .gitignore
			wantPkg2:       false, // Skipped because of IgnoreSubDirs
			wantInodeCount: 4,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			fc := &fakeCollector{}
			fsys := setupMapFS(t, tc.mapFS)
			config := &filesystem.Config{
				Extractors:     ex,
				PathsToExtract: []string{tc.pathToExtract},
				IgnoreSubDirs:  tc.ignoreSubDirs,
				UseGitignore:   true,
				ScanRoots: []*scalibrfs.ScanRoot{{
					FS: fsys, Path: ".",
				}},
				Stats:             fc,
				StoreAbsolutePath: false,
			}
			wc, err := filesystem.InitWalkContext(
				context.Background(), config, []*scalibrfs.ScanRoot{{
					FS: fsys, Path: cwd,
				}},
			)
			if err != nil {
				t.Fatalf("filesystem.InitializeWalkContext(..., %v): %v", fsys, err)
			}
			if err = wc.UpdateScanRoot(cwd, fsys); err != nil {
				t.Fatalf("wc.UpdateScanRoot(..., %v): %v", fsys, err)
			}
			gotInv, _, err := filesystem.RunFS(context.Background(), config, wc)
			if err != nil {
				t.Errorf("filesystem.RunFS(%v, %v): %v", config, wc, err)
			}

			if fc.AfterInodeVisitedCount != tc.wantInodeCount {
				t.Errorf("filesystem.RunFS(%v, %v) inodes visited: got %d, want %d", config, wc, fc.AfterInodeVisitedCount, tc.wantInodeCount)
			}

			gotPkg1 := slices.ContainsFunc(gotInv.Packages, func(p *extractor.Package) bool {
				return p.Name == name1
			})
			gotPkg2 := slices.ContainsFunc(gotInv.Packages, func(p *extractor.Package) bool {
				return p.Name == name2
			})
			if gotPkg1 != tc.wantPkg1 {
				t.Errorf("filesystem.Run(%v, %v): got inv1: %v, want: %v", config, wc, gotPkg1, tc.wantPkg1)
			}
			if gotPkg2 != tc.wantPkg2 {
				t.Errorf("filesystem.Run(%v, %v): got inv2: %v, want: %v", config, wc, gotPkg2, tc.wantPkg2)
			}
		})
	}
}

func setupMapFS(t *testing.T, mapFS mapFS) scalibrfs.FS {
	t.Helper()

	root := t.TempDir()
	for path, content := range mapFS {
		path = filepath.FromSlash(path)
		if content == nil {
			err := os.MkdirAll(filepath.Join(root, path), fs.ModePerm)
			if err != nil {
				t.Fatalf("os.MkdirAll(%q): %v", path, err)
			}
		} else {
			dir := filepath.Dir(path)
			err := os.MkdirAll(filepath.Join(root, dir), fs.ModePerm)
			if err != nil {
				t.Fatalf("os.MkdirAll(%q): %v", dir, err)
			}
			err = os.WriteFile(filepath.Join(root, path), content, fs.ModePerm)
			if err != nil {
				t.Fatalf("os.WriteFile(%q): %v", path, err)
			}
		}
	}
	return scalibrfs.DirFS(root)
}

// To not break the test every time we add a new metric, we inherit from the NoopCollector.
type fakeCollector struct {
	stats.NoopCollector
	AfterInodeVisitedCount int
}

func (c *fakeCollector) AfterInodeVisited(path string) { c.AfterInodeVisitedCount++ }

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
	wc, err := filesystem.InitWalkContext(context.Background(), config, config.ScanRoots)
	if err != nil {
		t.Fatalf("filesystem.InitializeWalkContext(%v): %v", config, err)
	}
	if err := wc.UpdateScanRoot(".", fsys); err != nil {
		t.Fatalf("wc.UpdateScanRoot(%v): %v", config, err)
	}
	gotInv, gotStatus, err := filesystem.RunFS(context.Background(), config, wc)
	if err != nil {
		t.Fatalf("extractor.Run(%v): %v", ex, err)
	}

	if !gotInv.IsEmpty() {
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
