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
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/gobwas/glob"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/location"
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
			desc: "valid_config_with_pathsToExtract_raises_no_error",
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
			desc: "valid_config_with_dirsToSkip_raises_no_error",
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
			desc: "pathsToExtract_not_relative_to_any_root_raises_error",
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
			desc: "dirsToSkip_not_relative_to_any_root_raises_error",
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
		{
			desc: "pathsToExtract_sharing_string_prefix_without_separator_raises_error",
			scanRoots: map[string][]string{
				"darwin":  {"/scanroot"},
				"linux":   {"/scanroot"},
				"windows": {"C:\\scanroot"},
			},
			pathsToExtract: map[string][]string{
				"darwin":  {"/scanroot_other/file1.txt"},
				"linux":   {"/scanroot_other/file1.txt"},
				"windows": {"C:\\scanroot_other\\file1.txt"},
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
				t.Context(), config, scanRoots,
			)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("filesystem.InitializeWalkContext(%v) error got diff (-want +got):\n%s", config, diff)
			}
		})
	}
}

// fakeExtractorFS is a mock extractor for testing embedded filesystem extraction.
// It simulates extracting an embedded filesystem from a VMDK file (e.g., disk.vmdk)
// and provides a function to return the embedded filesystem for scanning.
type fakeExtractorFS struct {
	name          string                                          // Name of the extractor (e.g., "fake-ex-fs").
	getEmbeddedFS func(ctx context.Context) (scalibrfs.FS, error) // Function to return the embedded filesystem for disk.vmdk:1.
}

func (e *fakeExtractorFS) Name() string                       { return e.name }
func (e *fakeExtractorFS) Version() int                       { return 1 }
func (e *fakeExtractorFS) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }
func (e *fakeExtractorFS) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	return path == "disk.vmdk"
}
func (e *fakeExtractorFS) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	path := input.Path
	if path != "disk.vmdk" {
		return inventory.Inventory{}, errors.New("unrecognized path")
	}
	return inventory.Inventory{
		EmbeddedFSs: []*inventory.EmbeddedFS{
			{
				Path:          "disk.vmdk:1",
				GetEmbeddedFS: e.getEmbeddedFS, // Use stored function
			},
		},
	}, nil
}

// fakeExtractorSoftware is a mock extractor for testing package detection.
// It simulates detecting a software package from a file (e.g., file.txt) within
// an embedded filesystem.
type fakeExtractorSoftware struct {
	name string // Name of the extractor (e.g., "fake-ex-software").
}

func (e *fakeExtractorSoftware) Name() string                       { return e.name }
func (e *fakeExtractorSoftware) Version() int                       { return 1 }
func (e *fakeExtractorSoftware) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }
func (e *fakeExtractorSoftware) FileRequired(api filesystem.FileAPI) bool {
	path := filepath.ToSlash(api.Path())
	return strings.HasSuffix(path, "file.txt") || strings.HasSuffix(path, "/file.txt") || path == "file.txt" || path == "./file.txt"
}
func (e *fakeExtractorSoftware) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	path := filepath.ToSlash(input.Path)
	if !strings.HasSuffix(path, "file.txt") {
		return inventory.Inventory{}, errors.New("not a file.txt")
	}
	return inventory.Inventory{
		Packages: []*extractor.Package{
			{
				Name:     "Software",
				Location: extractor.LocationFromPath(path),
				Plugins:  []string{e.Name()},
			},
		},
	}, nil
}

func TestRun_EmbeddedFS(t *testing.T) {
	success := &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}
	fsys := setupMapFS(t, mapFS{
		"disk.vmdk": []byte("VMDK Content"),
	})

	// Create temporary directory for embedded filesystem
	embeddedDir := t.TempDir()
	err := os.WriteFile(filepath.Join(embeddedDir, "file.txt"), []byte("Content"), fs.ModePerm)
	if err != nil {
		t.Fatalf("os.WriteFile(%q): %v", filepath.Join(embeddedDir, "file.txt"), err)
	}
	embeddedFS := scalibrfs.DirFS(embeddedDir)

	fakeExFS := &fakeExtractorFS{
		name: "fake-ex-fs",
		getEmbeddedFS: func(ctx context.Context) (scalibrfs.FS, error) {
			return embeddedFS, nil
		},
	}
	fakeExSoftware := &fakeExtractorSoftware{name: "fake-ex-software"}
	extractors := []filesystem.Extractor{fakeExFS, fakeExSoftware}

	// Create config with a single ScanRoot
	config := &filesystem.Config{
		Extractors: extractors,
		ScanRoots: []*scalibrfs.ScanRoot{{
			FS:   fsys,
			Path: ".",
		}},
		Stats: &fakeCollector{},
	}

	// Run the test
	gotInv, gotStatus, err := filesystem.Run(t.Context(), config)
	if err != nil {
		t.Fatalf("filesystem.Run(%v): %v", config, err)
	}

	// Expected inventory
	wantInv := inventory.Inventory{
		Packages: []*extractor.Package{
			{
				Name:     "Software",
				Location: extractor.LocationFromPath("disk.vmdk:1:file.txt"),
				Plugins:  []string{"fake-ex-software", "fake-ex-software"}, // Expect duplicate due to observed behavior
				ScanRoot: ".",
			},
		},
		EmbeddedFSs: []*inventory.EmbeddedFS{
			{
				Path:          "disk.vmdk:1",
				GetEmbeddedFS: fakeExFS.getEmbeddedFS,
			},
		},
	}

	// Expected status
	wantStatus := []*plugin.Status{
		{Name: "fake-ex-fs", Version: 1, Status: success},
		{Name: "fake-ex-software", Version: 1, Status: success},
	}

	// Sort package locations for comparison
	for _, p := range gotInv.Packages {
		slices.SortFunc(p.Location.Related, func(a, b location.Location) int {
			return strings.Compare(a.File.Path, b.File.Path)
		})
	}

	// Compare inventory
	if diff := cmp.Diff(wantInv, gotInv, cmpopts.SortSlices(extracttest.PackageCmpLess), fe.AllowUnexported, cmp.AllowUnexported(fakeExtractorFS{}, fakeExtractorSoftware{}), cmpopts.EquateErrors(), cmpopts.IgnoreFields(inventory.EmbeddedFS{}, "GetEmbeddedFS")); diff != "" {
		t.Errorf("filesystem.Run(%v): unexpected findings (-want +got):\n%s", config, diff)
	}

	// Deduplicate status entries, keeping the latest for each extractor
	seen := make(map[string]*plugin.Status)
	for _, s := range gotStatus {
		s.Status.FailureReason = ""
		seen[s.Name] = s
	}
	var dedupedStatus []*plugin.Status
	for _, s := range seen {
		dedupedStatus = append(dedupedStatus, s)
	}
	slices.SortFunc(dedupedStatus, func(a, b *plugin.Status) int {
		return strings.Compare(a.Name, b.Name)
	})

	// Compare status
	if diff := cmp.Diff(wantStatus, dedupedStatus, cmpopts.SortSlices(func(s1, s2 *plugin.Status) bool {
		return s1.Name < s2.Name
	})); diff != "" {
		t.Errorf("filesystem.Run(%v): unexpected status (-want +got):\n%s", config, diff)
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
			Name:     e.name,
			Location: extractor.LocationFromPath(path),
		}}}, nil
	}
	return inventory.Inventory{}, errors.New("unrecognized path")
}

func TestRun_EmbeddedFS_RunningSystem(t *testing.T) {
	fsys := setupMapFS(t, mapFS{
		"disk.vmdk": []byte("VMDK Content"),
	})

	// Create temporary directory for embedded filesystem
	embeddedDir := t.TempDir()
	err := os.WriteFile(filepath.Join(embeddedDir, "file.txt"), []byte("Content"), fs.ModePerm)
	if err != nil {
		t.Fatalf("os.WriteFile(%q): %v", filepath.Join(embeddedDir, "file.txt"), err)
	}
	embeddedFS := scalibrfs.DirFS(embeddedDir)

	fakeExFS := &fakeExtractorFS{
		name: "fake-ex-fs",
		getEmbeddedFS: func(ctx context.Context) (scalibrfs.FS, error) {
			return embeddedFS, nil
		},
	}
	fakeExSoftware := &fakeExtractorSoftware{name: "fake-ex-software"}

	// Use fakeextractor.NewWithRequirements to create a mock extractor requiring a running system.
	fakeExRunningSystem := fe.NewWithRequirements(
		"fake-ex-runningsystem",
		1,
		[]string{"file.txt"},
		map[string]fe.NamesErr{"file.txt": {Names: []string{"RunningSystemSoftware"}, Err: nil}},
		&plugin.Capabilities{RunningSystem: true},
	)

	// We include the running system extractor.
	extractors := []filesystem.Extractor{fakeExFS, fakeExSoftware, fakeExRunningSystem}

	config := &filesystem.Config{
		Extractors: extractors,
		ScanRoots: []*scalibrfs.ScanRoot{{
			FS:   fsys,
			Path: ".",
		}},
		Stats: &fakeCollector{},
	}

	// Run the test
	gotInv, _, err := filesystem.Run(t.Context(), config)
	if err != nil {
		t.Fatalf("filesystem.Run(%v): %v", config, err)
	}

	// We expect to find "Software" from fakeExSoftware, but NOT "RunningSystemSoftware" from fakeExRunningSystem.
	wantInv := inventory.Inventory{
		Packages: []*extractor.Package{
			{
				Name:     "Software",
				Location: extractor.LocationFromPath("disk.vmdk:1:file.txt"),
				Plugins:  []string{"fake-ex-software", "fake-ex-software"},
				ScanRoot: ".",
			},
		},
		EmbeddedFSs: []*inventory.EmbeddedFS{
			{
				Path:          "disk.vmdk:1",
				GetEmbeddedFS: fakeExFS.getEmbeddedFS,
			},
		},
	}

	if diff := cmp.Diff(wantInv, gotInv, cmpopts.SortSlices(extracttest.PackageCmpLess), fe.AllowUnexported, cmp.AllowUnexported(fakeExtractorFS{}, fakeExtractorSoftware{}), cmpopts.EquateErrors(), cmpopts.IgnoreFields(inventory.EmbeddedFS{}, "GetEmbeddedFS")); diff != "" {
		t.Errorf("filesystem.Run(%v): unexpected findings (-want +got):\n%s", config, diff)
	}
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
		maxInodes        int
		maxFileSizeBytes int64
		wantErr          error
		wantPkg          inventory.Inventory
		wantStatus       []*plugin.Status
		wantInodeCount   int
	}{
		{
			desc: "Extractors_successful",
			ex:   []filesystem.Extractor{fakeEx1, fakeEx2},
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:     name1,
					Location: extractor.LocationFromPath(path1),
					Plugins:  []string{fakeEx1.Name()},
				},
				{
					Name:     name2,
					Location: extractor.LocationFromPath(path2),
					Plugins:  []string{fakeEx2.Name()},
				},
			}},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Dir_skipped",
			ex:   []filesystem.Extractor{fakeEx1, fakeEx2},
			// ScanRoot is CWD
			dirsToSkip: []string{path.Join(cwd, "dir1")},
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:     name2,
					Location: extractor.LocationFromPath(path2),
					Plugins:  []string{fakeEx2.Name()},
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
					Name:     name2,
					Location: extractor.LocationFromPath(path2),
					Plugins:  []string{fakeEx2.Name()},
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
					Name:     name2,
					Location: extractor.LocationFromPath(path2),
					Plugins:  []string{fakeEx2.Name()},
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
					Name:     name1,
					Location: extractor.LocationFromPath(path1),
					Plugins:  []string{fakeEx1.Name()},
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
					Name:     name1,
					Location: extractor.LocationFromPath(path1),
					Plugins:  []string{fakeEx1.Name()},
				},
				{
					Name:     name2,
					Location: extractor.LocationFromPath(path2),
					Plugins:  []string{fakeEx2.Name()},
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
					Name:     name1,
					Location: extractor.LocationFromPath(path1),
					Plugins:  []string{fakeEx1.Name()},
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
					Name:     name1,
					Location: extractor.LocationFromPath(path1),
					Plugins:  []string{fakeEx1.Name()},
				},
				{
					Name:     name2,
					Location: extractor.LocationFromPath(path2),
					Plugins:  []string{fakeEx2.Name()},
				},
			}},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Duplicate_inventory_results_kept_separate",
			ex:   []filesystem.Extractor{fakeEx1, fakeEx2WithPKG1},
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:     name1,
					Location: extractor.LocationFromPath(path1),
					Plugins:  []string{fakeEx1.Name()},
				},
				{
					Name:     name1,
					Location: extractor.LocationFromPath(path2),
					Plugins:  []string{fakeEx2WithPKG1.Name()},
				},
			}},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Extract_specific_file",
			ex:   []filesystem.Extractor{fakeEx1, fakeEx2},
			// ScanRoot is CWD
			pathsToExtract: []string{path.Join(cwd, path2)},
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:     name2,
					Location: extractor.LocationFromPath(path2),
					Plugins:  []string{fakeEx2.Name()},
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
					Name:     name2,
					Location: extractor.LocationFromPath(path2),
					Plugins:  []string{fakeEx2.Name()},
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
					Name:     name2,
					Location: extractor.LocationFromPath(path2),
					Plugins:  []string{fakeEx2.Name()},
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
					Name:     name1,
					Location: extractor.LocationFromPath(path1),
					Plugins:  []string{fakeEx1.Name()},
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
			desc: "nil_result",
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
			desc: "Extraction_fails_with_partial_results",
			ex:   []filesystem.Extractor{fakeExWithPartialResult},
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:     name1,
					Location: extractor.LocationFromPath(path1),
					Plugins:  []string{fakeExWithPartialResult.Name()},
				},
			}},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: &plugin.ScanStatus{
					Status:        plugin.ScanStatusPartiallySucceeded,
					FailureReason: "encountered 1 error(s) while running plugin; check file-specific errors for details",
					FileErrors: []*plugin.FileError{
						{FilePath: path1, ErrorMessage: "extraction failed"},
					},
				}},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Extraction_fails_with_no_results",
			ex: []filesystem.Extractor{
				fe.New("ex1", 1, []string{path1}, map[string]fe.NamesErr{path1: {Names: nil, Err: errors.New("extraction failed")}}),
			},
			wantPkg: inventory.Inventory{},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: &plugin.ScanStatus{
					Status:        plugin.ScanStatusFailed,
					FailureReason: "encountered 1 error(s) while running plugin; check file-specific errors for details",
					FileErrors: []*plugin.FileError{
						{FilePath: path1, ErrorMessage: "extraction failed"},
					},
				}},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Extraction_fails_several_times",
			ex: []filesystem.Extractor{
				fe.New("ex1", 1, []string{path1, path2}, map[string]fe.NamesErr{
					path1: {Names: nil, Err: errors.New("extraction failed")},
					path2: {Names: nil, Err: errors.New("extraction failed")},
				}),
			},
			wantPkg: inventory.Inventory{},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: &plugin.ScanStatus{
					Status:        plugin.ScanStatusFailed,
					FailureReason: "encountered 2 error(s) while running plugin; check file-specific errors for details",
					FileErrors: []*plugin.FileError{
						{FilePath: path1, ErrorMessage: "extraction failed"},
						{FilePath: path2, ErrorMessage: "extraction failed"},
					},
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
					Name:     name1,
					Location: extractor.LocationFromPath(path1),
					Plugins:  []string{fakeEx1.Name()},
				},
				{
					Name:     name2,
					Location: extractor.LocationFromPath(path2),
					Plugins:  []string{fakeEx2.Name()},
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
					Name:     name1,
					Location: extractor.LocationFromPath(path1),
					Plugins:  []string{fakeEx1.Name()},
				},
			}},
			wantStatus: []*plugin.Status{
				{Name: "ex1", Version: 1, Status: success},
				{Name: "ex2", Version: 2, Status: success},
			},
			wantInodeCount: 6,
		},
		{
			desc: "Extractor_runs_on_directory",
			ex:   []filesystem.Extractor{fakeEx1, fakeExDirs},
			wantPkg: inventory.Inventory{Packages: []*extractor.Package{
				{
					Name:     name1,
					Location: extractor.LocationFromPath(path1),
					Plugins:  []string{fakeEx1.Name()},
				},
				{
					Name:     name2,
					Location: extractor.LocationFromPath(dir1),
					Plugins:  []string{fakeExDirs.Name()},
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
			var skipDirGlob *glob.Pattern
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
				Stats: fc,
			}
			wc, err := filesystem.InitWalkContext(
				t.Context(), config, []*scalibrfs.ScanRoot{{
					FS: fsys, Path: cwd,
				}},
			)
			if err != nil {
				t.Fatalf("filesystem.InitializeWalkContext(..., %v): %v", fsys, err)
			}
			if err = wc.PrepareNewScan(cwd, fsys); err != nil {
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
			for _, p := range gotInv.Packages {
				slices.SortFunc(p.Location.Related, func(a, b location.Location) int {
					return strings.Compare(a.File.Path, b.File.Path)
				})
			}

			if diff := cmp.Diff(tc.wantPkg, gotInv, cmpopts.SortSlices(extracttest.PackageCmpLess), fe.AllowUnexported, cmp.AllowUnexported(fakeExtractorDirs{}), cmpopts.EquateErrors()); diff != "" {
				t.Errorf("extractor.Run(%v): unexpected findings (-want +got):\n%s", tc.ex, diff)
			}

			// The order of the statuses doesn't matter.
			for _, s := range gotStatus {
				if s.Status.FileErrors != nil {
					slices.SortFunc(s.Status.FileErrors, func(a, b *plugin.FileError) int {
						return strings.Compare(a.FilePath, b.FilePath)
					})
				}
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
				Stats: fc,
			}
			wc, err := filesystem.InitWalkContext(
				t.Context(), config, []*scalibrfs.ScanRoot{{
					FS: fsys, Path: cwd,
				}},
			)
			if err != nil {
				t.Fatalf("filesystem.InitializeWalkContext(..., %v): %v", fsys, err)
			}
			if err = wc.PrepareNewScan(cwd, fsys); err != nil {
				t.Fatalf("wc.UpdateScanRoot(..., %v): %v", fsys, err)
			}
			gotInv, _, err := filesystem.RunFS(t.Context(), config, wc)
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
	return fakefs.DirFS(t, root)
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
			Status: plugin.ScanStatusFailed, FailureReason: "encountered 1 error(s) while running plugin; check file-specific errors for details", FileErrors: []*plugin.FileError{
				{FilePath: "file", ErrorMessage: "Open(file): failed to open"},
			},
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
	if err := wc.PrepareNewScan(".", fsys); err != nil {
		t.Fatalf("wc.UpdateScanRoot(%v): %v", config, err)
	}
	gotInv, gotStatus, err := filesystem.RunFS(t.Context(), config, wc)
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
			name: "user_executable",
			path: "some/path/a",
			mode: 0766,
			want: true,
		},
		{
			name: "group_executable",
			path: "some/path/a",
			mode: 0676,
			want: true,
		},
		{
			name: "other_executable",
			path: "some/path/a",
			mode: 0667,
			want: true,
		},
		{
			name: "windows_exe",
			path: "some/path/a.exe",
			mode: 0666,
			want: true,
		},
		{
			name: "windows_dll",
			path: "some/path/a.dll",
			mode: 0666,
			want: true,
		},
		{
			name:        "not executable bit set",
			path:        "some/path/a",
			mode:        0640,
			want:        false,
			wantWindows: false,
		},
		{
			name: "executable_required",
			path: "some/path/a",
			mode: 0766,
			want: true,
		},
		{
			name: "unwanted_extension",
			path: "some/path/a.html",
			mode: 0766,
			want: false,
		},
		{
			name: "another_unwanted_extension",
			path: "some/path/a.txt",
			mode: 0766,
			want: false,
		},
		{
			name: "python_script_without_execute_permissions",
			path: "some/path/a.py",
			mode: 0666,
			want: true,
		},
		{
			name: "shell_script_without_execute_permissions",
			path: "some/path/a.sh",
			mode: 0666,
			want: true,
		},
		{
			name: "shared_library_without_execute_permissions",
			path: "some/path/a.so",
			mode: 0666,
			want: true,
		},
		{
			name: "binary_file_without_execute_permissions",
			path: "some/path/a.bin",
			mode: 0666,
			want: true,
		},
		{
			name: "versioned_shared_library",
			path: "some/path/library.so.1",
			mode: 0666,
			want: true,
		},
		{
			name: "versioned_shared_library_with_multiple_digits",
			path: "some/path/library.so.12",
			mode: 0666,
			want: true,
		},
		{
			name: "not_a_versioned_shared_library",
			path: "some/path/library.so.foo",
			mode: 0666,
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

type statErrEntry struct {
	fs.DirEntry

	err   error
	calls *int
}

func (e statErrEntry) Info() (fs.FileInfo, error) {
	if e.calls != nil {
		*e.calls++
	}
	return nil, e.err
}

type statErrFS struct {
	fstest.MapFS

	err       error
	infoCalls *int
}

// Open returns ErrUnsupported so diriterate.ReadDir uses ReadDir instead of MapFS's ReadDirFile.
func (statErrFS) Open(_ string) (fs.File, error) {
	return nil, errors.ErrUnsupported
}

func (f statErrFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := f.MapFS.ReadDir(name)
	if err != nil {
		return nil, err
	}
	for i, e := range entries {
		if !e.IsDir() {
			entries[i] = statErrEntry{DirEntry: e, err: f.err, calls: f.infoCalls}
		}
	}
	return entries, nil
}

type statCapturingExtractor struct {
	targetPath string
	called     bool
	firstErr   error
	secondErr  error
}

func (*statCapturingExtractor) Name() string                       { return "test/stat-capture" }
func (*statCapturingExtractor) Version() int                       { return 0 }
func (*statCapturingExtractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }
func (e *statCapturingExtractor) FileRequired(api filesystem.FileAPI) bool {
	if api.Path() == e.targetPath {
		e.called = true
		_, e.firstErr = api.Stat()
		_, e.secondErr = api.Stat()
	}
	return false
}
func (*statCapturingExtractor) Extract(_ context.Context, _ *filesystem.ScanInput) (inventory.Inventory, error) {
	return inventory.Inventory{}, nil
}

func TestRun_LazyFileAPIStatCachesEntryInfoError(t *testing.T) {
	sentinel := errors.New("injected entry stat failure")
	infoCalls := 0
	fsys := statErrFS{
		MapFS: fstest.MapFS{
			"a/b/leaf.txt": &fstest.MapFile{Data: []byte("hello")},
		},
		err:       &fs.PathError{Op: "lstat", Path: "leaf.txt", Err: sentinel},
		infoCalls: &infoCalls,
	}
	ex := &statCapturingExtractor{targetPath: "a/b/leaf.txt"}

	_, _, err := filesystem.Run(t.Context(), &filesystem.Config{
		Stats:      stats.NoopCollector{},
		ScanRoots:  []*scalibrfs.ScanRoot{{FS: fsys}},
		Extractors: []filesystem.Extractor{ex},
	})
	if err != nil {
		t.Fatalf("filesystem.Run: %v", err)
	}
	if !ex.called {
		t.Fatal("statCapturingExtractor was never invoked for a/b/leaf.txt")
	}
	if !errors.Is(ex.firstErr, sentinel) {
		t.Fatalf("api.Stat() error = %v, want %v", ex.firstErr, sentinel)
	}
	if infoCalls != 1 {
		t.Errorf("DirEntry.Info() called %d times across 2 api.Stat() calls, want 1 (cached)", infoCalls)
	}
	if !errors.Is(ex.secondErr, sentinel) {
		t.Errorf("second api.Stat() error = %v, want cached %v", ex.secondErr, sentinel)
	}
}

type countingDirEntry struct {
	fs.DirEntry

	calls *int
}

func (e countingDirEntry) Info() (fs.FileInfo, error) {
	if e.calls != nil {
		*e.calls++
	}
	return e.DirEntry.Info()
}

type countingEntryFS struct {
	fstest.MapFS

	infoCalls *int
	statCalls *int
}

// Open returns ErrUnsupported on directories so diriterate.ReadDir uses ReadDir.
func (f countingEntryFS) Open(name string) (fs.File, error) {
	if name == "." || name == "a" {
		return nil, errors.ErrUnsupported
	}
	return f.MapFS.Open(name)
}

func (f countingEntryFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := f.MapFS.ReadDir(name)
	if err != nil {
		return nil, err
	}
	for i, e := range entries {
		if !e.IsDir() {
			entries[i] = countingDirEntry{DirEntry: e, calls: f.infoCalls}
		}
	}
	return entries, nil
}

func (f countingEntryFS) Stat(name string) (fs.FileInfo, error) {
	if name == "." || name == "a" {
		return f.MapFS.Stat(name)
	}
	if f.statCalls != nil {
		*f.statCalls++
	}
	return nil, errors.New("unexpected file FS.Stat call")
}

type multiFileStatExtractor struct {
	gotSizes      map[string]int64
	mismatchCache bool
	statErr       error
}

func (*multiFileStatExtractor) Name() string                       { return "test/multi-stat" }
func (*multiFileStatExtractor) Version() int                       { return 0 }
func (*multiFileStatExtractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }
func (e *multiFileStatExtractor) FileRequired(api filesystem.FileAPI) bool {
	info1, err1 := api.Stat()
	info2, err2 := api.Stat()
	if err1 != nil {
		e.statErr = err1
		return false
	}
	if err2 != nil {
		e.statErr = err2
		return false
	}
	if info2 != info1 {
		e.mismatchCache = true
	}
	e.gotSizes[api.Path()] = info1.Size()
	return false
}
func (*multiFileStatExtractor) Extract(_ context.Context, _ *filesystem.ScanInput) (inventory.Inventory, error) {
	return inventory.Inventory{}, nil
}

func TestRun_LazyFileAPIStatReusesDirEntryInfoAndResetsAcrossFiles(t *testing.T) {
	infoCalls := 0
	statCalls := 0
	fsys := countingEntryFS{
		MapFS: fstest.MapFS{
			"a/first.txt":  &fstest.MapFile{Data: []byte("hello")},
			"a/second.txt": &fstest.MapFile{Data: []byte("hello world")},
		},
		infoCalls: &infoCalls,
		statCalls: &statCalls,
	}
	ex := &multiFileStatExtractor{gotSizes: make(map[string]int64)}

	_, _, err := filesystem.Run(t.Context(), &filesystem.Config{
		Stats:      stats.NoopCollector{},
		ScanRoots:  []*scalibrfs.ScanRoot{{FS: fsys}},
		Extractors: []filesystem.Extractor{ex},
	})
	if err != nil {
		t.Fatalf("filesystem.Run: %v", err)
	}
	if ex.statErr != nil {
		t.Fatalf("api.Stat() unexpected error: %v", ex.statErr)
	}
	if ex.mismatchCache {
		t.Errorf("second api.Stat() on same file did not return cached fs.FileInfo")
	}
	if statCalls != 0 {
		t.Errorf("non-root FS.Stat calls = %d, want 0", statCalls)
	}
	if infoCalls != 2 {
		t.Errorf("DirEntry.Info() calls = %d across 2 files (4 api.Stat calls), want 2", infoCalls)
	}
	wantSizes := map[string]int64{"a/first.txt": 5, "a/second.txt": 11}
	if diff := cmp.Diff(wantSizes, ex.gotSizes); diff != "" {
		t.Errorf("api.Stat() sizes diff (-want +got):\n%s", diff)
	}
}

type symlinkTargetFS struct {
	fstest.MapFS

	infoCalls *int
	statCalls *int
}

// Open returns ErrUnsupported on directories so diriterate.ReadDir uses ReadDir,
// and resolves "link.bin" to "target.bin" when opened by an extractor.
func (f symlinkTargetFS) Open(name string) (fs.File, error) {
	if name == "." {
		return nil, errors.ErrUnsupported
	}
	if name == "link.bin" {
		return f.MapFS.Open("target.bin")
	}
	return f.MapFS.Open(name)
}

func (f symlinkTargetFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := f.MapFS.ReadDir(name)
	if err != nil {
		return nil, err
	}
	for i, e := range entries {
		if e.Name() == "link.bin" {
			entries[i] = countingDirEntry{DirEntry: e, calls: f.infoCalls}
		}
	}
	return entries, nil
}

func (f symlinkTargetFS) Stat(name string) (fs.FileInfo, error) {
	if name == "link.bin" {
		if f.statCalls != nil {
			*f.statCalls++
		}
		return f.MapFS.Stat("target.bin")
	}
	return f.MapFS.Stat(name)
}

type symlinkStatExtractor struct {
	targetPath string
	gotMode    fs.FileMode
	gotSize    int64
	statErr    error
	extracted  int
}

func (*symlinkStatExtractor) Name() string                       { return "test/symlink-stat" }
func (*symlinkStatExtractor) Version() int                       { return 0 }
func (*symlinkStatExtractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }
func (e *symlinkStatExtractor) FileRequired(api filesystem.FileAPI) bool {
	if api.Path() != e.targetPath {
		return false
	}
	info, err := api.Stat()
	if err != nil {
		e.statErr = err
		return false
	}
	e.gotMode = info.Mode()
	e.gotSize = info.Size()
	return true
}
func (e *symlinkStatExtractor) Extract(_ context.Context, _ *filesystem.ScanInput) (inventory.Inventory, error) {
	e.extracted++
	return inventory.Inventory{}, nil
}

func TestRun_LazyFileAPIStatSymlinkUsesFSStat(t *testing.T) {
	tests := []struct {
		name          string
		maxFileSize   int64
		wantExtracted int
	}{
		{
			name:          "extracts_when_within_max_file_size",
			maxFileSize:   200,
			wantExtracted: 1,
		},
		{
			name:          "skips_when_target_exceeds_max_file_size",
			maxFileSize:   50,
			wantExtracted: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			infoCalls := 0
			statCalls := 0
			fsys := symlinkTargetFS{
				MapFS: fstest.MapFS{
					"target.bin": &fstest.MapFile{Data: []byte(strings.Repeat("x", 100))},
					// Symlink data is 10 bytes (<= 50), whereas target.bin is 100 bytes (> 50).
					"link.bin": &fstest.MapFile{Data: []byte("target.bin"), Mode: fs.ModeSymlink | 0o777},
				},
				infoCalls: &infoCalls,
				statCalls: &statCalls,
			}
			ex := &symlinkStatExtractor{targetPath: "link.bin"}

			_, _, err := filesystem.Run(t.Context(), &filesystem.Config{
				Stats:        stats.NoopCollector{},
				ScanRoots:    []*scalibrfs.ScanRoot{{FS: fsys}},
				Extractors:   []filesystem.Extractor{ex},
				ReadSymlinks: true,
				MaxFileSize:  tc.maxFileSize,
			})
			if err != nil {
				t.Fatalf("filesystem.Run(MaxFileSize=%d): %v", tc.maxFileSize, err)
			}
			if ex.statErr != nil {
				t.Fatalf("api.Stat() on symlink failed: %v", ex.statErr)
			}
			if infoCalls != 0 {
				t.Errorf("symlink DirEntry.Info() calls = %d, want 0", infoCalls)
			}
			if statCalls != 1 {
				t.Errorf("symlink FS.Stat calls = %d, want 1", statCalls)
			}
			if !ex.gotMode.IsRegular() {
				t.Errorf("api.Stat().Mode() = %v, want regular target mode", ex.gotMode)
			}
			if ex.gotSize != 100 {
				t.Errorf("api.Stat().Size() = %d, want 100", ex.gotSize)
			}
			if ex.extracted != tc.wantExtracted {
				t.Errorf("Extract calls (MaxFileSize=%d) = %d, want %d", tc.maxFileSize, ex.extracted, tc.wantExtracted)
			}
		})
	}
}
