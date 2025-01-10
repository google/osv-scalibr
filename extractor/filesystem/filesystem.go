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

// Package filesystem provides the interface for inventory extraction plugins.
package filesystem

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gobwas/glob"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/internal"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"
)

var (
	// ErrNotRelativeToScanRoots is returned when one of the file or directory to be retrieved or
	// skipped is not relative to any of the scan roots.
	ErrNotRelativeToScanRoots = fmt.Errorf("path not relative to any of the scan roots")
)

// Extractor is the filesystem-based inventory extraction plugin, used to extract inventory data
// from the filesystem such as OS and language packages.
type Extractor interface {
	extractor.Extractor
	// FileRequired should return true if the file described by path and file info is
	// relevant for the extractor.
	// Note that the plugin doesn't traverse the filesystem itself but relies on the core
	// library for that.
	FileRequired(api FileAPI) bool
	// Extract extracts inventory data relevant for the extractor from a given file.
	Extract(ctx context.Context, input *ScanInput) ([]*extractor.Inventory, error)
}

// FileAPI is the interface for accessing file information and path.
type FileAPI interface {
	// Stat returns the file info for the file.
	Stat() (fs.FileInfo, error)
	Path() string
}

// ScanInput describes one file to extract from.
type ScanInput struct {
	// FS for file access. This is rooted at Root.
	FS scalibrfs.FS
	// The path of the file to extract, relative to Root.
	Path string
	// The root directory where the extraction file walking started from.
	Root string
	Info fs.FileInfo
	// A reader for accessing contents of the file.
	// Note that the file is closed by the core library, not the plugin.
	Reader io.Reader
}

// Config stores the config settings for an extraction run.
type Config struct {
	Extractors []Extractor
	ScanRoots  []*scalibrfs.ScanRoot
	// Optional: Individual files to extract inventory from. If specified, the
	// extractors will only look at these files during the filesystem traversal.
	// Note that these are not relative to the ScanRoots and thus need to be
	// sub-directories of one of the ScanRoots.
	FilesToExtract []string
	// Optional: Directories that the file system walk should ignore.
	// Note that these are not relative to the ScanRoots and thus need to be
	// sub-directories of one of the ScanRoots.
	// TODO(b/279413691): Also skip local paths, e.g. "Skip all .git dirs"
	DirsToSkip []string
	// Optional: If the regex matches a directory, it will be skipped.
	SkipDirRegex *regexp.Regexp
	// Optional: If the regex matches a glob, it will be skipped.
	SkipDirGlob glob.Glob
	// Optional: stats allows to enter a metric hook. If left nil, no metrics will be recorded.
	Stats stats.Collector
	// Optional: Whether to read symlinks.
	ReadSymlinks bool
	// Optional: Limit for visited inodes. If 0, no limit is applied.
	MaxInodes int
	// Optional: By default, inventories stores a path relative to the scan root. If StoreAbsolutePath
	// is set, the absolute path is stored instead.
	StoreAbsolutePath bool
	// Optional: If true, print a detailed analysis of the duration of each extractor.
	PrintDurationAnalysis bool
	// Optional: If true, fail the scan if any permission errors are encountered.
	ErrorOnFSErrors bool
}

// Run runs the specified extractors and returns their extraction results,
// as well as info about whether the plugin runs completed successfully.
func Run(ctx context.Context, config *Config) ([]*extractor.Inventory, []*plugin.Status, error) {
	if len(config.Extractors) == 0 {
		return []*extractor.Inventory{}, []*plugin.Status{}, nil
	}

	scanRoots, err := expandAllAbsolutePaths(config.ScanRoots)
	if err != nil {
		return nil, nil, err
	}

	wc, err := InitWalkContext(ctx, config, scanRoots)
	if err != nil {
		return nil, nil, err
	}

	var inventory []*extractor.Inventory
	var status []*plugin.Status

	for _, root := range scanRoots {
		inv, st, err := runOnScanRoot(ctx, config, root, wc)
		if err != nil {
			return nil, nil, err
		}

		inventory = append(inventory, inv...)
		status = append(status, st...)
	}

	return inventory, status, nil
}

func runOnScanRoot(ctx context.Context, config *Config, scanRoot *scalibrfs.ScanRoot, wc *walkContext) ([]*extractor.Inventory, []*plugin.Status, error) {
	abs := ""
	var err error
	if !scanRoot.IsVirtual() {
		abs, err = filepath.Abs(scanRoot.Path)
		if err != nil {
			return nil, nil, err
		}
	}
	if err = wc.UpdateScanRoot(abs, scanRoot.FS); err != nil {
		return nil, nil, err
	}

	return RunFS(ctx, config, wc)
}

// InitWalkContext initializes the walk context for a filesystem walk. It strips all the paths that
// are expected to be relative to the scan root.
// This function is exported for TESTS ONLY.
func InitWalkContext(ctx context.Context, config *Config, absScanRoots []*scalibrfs.ScanRoot) (*walkContext, error) {
	filesToExtract, err := stripAllPathPrefixes(config.FilesToExtract, absScanRoots)
	if err != nil {
		return nil, err
	}
	dirsToSkip, err := stripAllPathPrefixes(config.DirsToSkip, absScanRoots)
	if err != nil {
		return nil, err
	}

	return &walkContext{
		ctx:               ctx,
		stats:             config.Stats,
		extractors:        config.Extractors,
		filesToExtract:    filesToExtract,
		dirsToSkip:        pathStringListToMap(dirsToSkip),
		skipDirRegex:      config.SkipDirRegex,
		skipDirGlob:       config.SkipDirGlob,
		readSymlinks:      config.ReadSymlinks,
		maxInodes:         config.MaxInodes,
		inodesVisited:     0,
		storeAbsolutePath: config.StoreAbsolutePath,
		errorOnFSErrors:   config.ErrorOnFSErrors,

		lastStatus: time.Now(),

		inventory: []*extractor.Inventory{},
		errors:    make(map[string]error),
		foundInv:  make(map[string]bool),

		fileAPI: &lazyFileAPI{},
	}, nil
}

// RunFS runs the specified extractors and returns their extraction results,
// as well as info about whether the plugin runs completed successfully.
// scanRoot is the location of fsys.
// This method is for testing, use Run() to avoid confusion with scanRoot vs fsys.
func RunFS(ctx context.Context, config *Config, wc *walkContext) ([]*extractor.Inventory, []*plugin.Status, error) {
	start := time.Now()
	if wc == nil || wc.fs == nil {
		return nil, nil, fmt.Errorf("walk context is nil")
	}

	var err error
	log.Infof("Starting filesystem walk for root: %v", wc.scanRoot)
	if len(wc.filesToExtract) > 0 {
		err = walkIndividualFiles(wc.fs, wc.filesToExtract, wc.handleFile)
	} else {
		ticker := time.NewTicker(2 * time.Second)
		quit := make(chan struct{})
		go func() {
			for {
				select {
				case <-ticker.C:
					wc.printStatus()
				case <-quit:
					ticker.Stop()
					return
				}
			}
		}()

		err = internal.WalkDirUnsorted(wc.fs, ".", wc.handleFile)

		close(quit)
	}

	// On Windows, elapsed and wall time are probably the same. On Linux and Mac they are different,
	// if Scalibr was suspended during runtime.
	log.Infof("End status: %d dirs visited, %d inodes visited, %d Extract calls, %s elapsed, %s wall time",
		wc.dirsVisited, wc.inodesVisited, wc.extractCalls, time.Since(start), time.Duration(time.Now().UnixNano()-start.UnixNano()))

	return wc.inventory, errToExtractorStatus(config.Extractors, wc.foundInv, wc.errors), err
}

type walkContext struct {
	ctx               context.Context
	stats             stats.Collector
	extractors        []Extractor
	fs                scalibrfs.FS
	scanRoot          string
	filesToExtract    []string
	dirsToSkip        map[string]bool // Anything under these paths should be skipped.
	skipDirRegex      *regexp.Regexp
	skipDirGlob       glob.Glob
	maxInodes         int
	inodesVisited     int
	dirsVisited       int
	storeAbsolutePath bool
	errorOnFSErrors   bool

	// Inventories found.
	inventory []*extractor.Inventory
	// Extractor name to runtime errors.
	errors map[string]error
	// Whether an extractor found any inventory.
	foundInv map[string]bool
	// Whether to read symlinks.
	readSymlinks bool

	// Data for status printing.
	lastStatus   time.Time
	lastInodes   int
	extractCalls int
	lastExtracts int

	currentPath string
	fileAPI     *lazyFileAPI
}

func walkIndividualFiles(fsys scalibrfs.FS, paths []string, fn fs.WalkDirFunc) error {
	for _, p := range paths {
		info, err := fs.Stat(fsys, p)
		if err != nil {
			err = fn(p, nil, err)
		} else {
			err = fn(p, fs.FileInfoToDirEntry(info), nil)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (wc *walkContext) handleFile(path string, d fs.DirEntry, fserr error) error {
	wc.currentPath = path

	wc.inodesVisited++
	if wc.maxInodes > 0 && wc.inodesVisited > wc.maxInodes {
		return fmt.Errorf("maxInodes (%d) exceeded", wc.maxInodes)
	}

	wc.stats.AfterInodeVisited(path)
	if wc.ctx.Err() != nil {
		return wc.ctx.Err()
	}
	if fserr != nil {
		if wc.errorOnFSErrors {
			return fmt.Errorf("handleFile(%q) fserr: %w", path, fserr)
		}
		if os.IsPermission(fserr) {
			// Permission errors are expected when traversing the entire filesystem.
			log.Debugf("fserr (permission error): %v", fserr)
		} else {
			log.Errorf("fserr (non-permission error): %v", fserr)
		}
		return nil
	}
	if d.Type().IsDir() {
		wc.dirsVisited++
		if wc.shouldSkipDir(path) { // Skip everything inside this dir.
			return fs.SkipDir
		}
		return nil
	}

	// Ignore non regular files except symlinks.
	if !d.Type().IsRegular() {
		// Ignore the file because symlink reading is disabled.
		if !wc.readSymlinks {
			return nil
		}
		// Ignore non-symlinks.
		if (d.Type() & fs.ModeType) != fs.ModeSymlink {
			return nil
		}
	}

	wc.fileAPI.currentPath = path
	wc.fileAPI.currentStatCalled = false

	for _, ex := range wc.extractors {
		if ex.FileRequired(wc.fileAPI) {
			wc.runExtractor(ex, path)
		}
	}
	return nil
}

type lazyFileAPI struct {
	fs                scalibrfs.FS
	currentPath       string
	currentFileInfo   fs.FileInfo
	currentStatErr    error
	currentStatCalled bool
}

func (api *lazyFileAPI) Path() string {
	return api.currentPath
}
func (api *lazyFileAPI) Stat() (fs.FileInfo, error) {
	if !api.currentStatCalled {
		api.currentStatCalled = true
		api.currentFileInfo, api.currentStatErr = fs.Stat(api.fs, api.currentPath)
	}
	return api.currentFileInfo, api.currentStatErr
}

func (wc *walkContext) shouldSkipDir(path string) bool {
	if _, ok := wc.dirsToSkip[path]; ok {
		return true
	}
	if wc.skipDirRegex != nil {
		return wc.skipDirRegex.MatchString(path)
	}
	if wc.skipDirGlob != nil {
		return wc.skipDirGlob.Match(path)
	}
	return false
}

func (wc *walkContext) runExtractor(ex Extractor, path string) {
	rc, err := wc.fs.Open(path)
	if err != nil {
		addErrToMap(wc.errors, ex.Name(), fmt.Errorf("Open(%s): %v", path, err))
		return
	}
	defer rc.Close()

	info, err := rc.Stat()
	if err != nil {
		addErrToMap(wc.errors, ex.Name(), fmt.Errorf("stat(%s): %v", path, err))
		return
	}

	wc.extractCalls++

	start := time.Now()
	results, err := ex.Extract(wc.ctx, &ScanInput{
		FS:     wc.fs,
		Path:   path,
		Root:   wc.scanRoot,
		Info:   info,
		Reader: rc,
	})
	wc.stats.AfterExtractorRun(ex.Name(), time.Since(start), err)

	if err != nil {
		addErrToMap(wc.errors, ex.Name(), fmt.Errorf("%s: %w", path, err))
	}

	if len(results) > 0 {
		wc.foundInv[ex.Name()] = true
		for _, r := range results {
			r.Extractor = ex
			if wc.storeAbsolutePath {
				r.Locations = expandAbsolutePath(wc.scanRoot, r.Locations)
			}
			wc.inventory = append(wc.inventory, r)
		}
	}
}

// UpdateScanRoot updates the scan root and the filesystem to use for the filesystem walk.
// currentRoot is expected to be an absolute path.
func (wc *walkContext) UpdateScanRoot(absRoot string, fs scalibrfs.FS) error {
	wc.scanRoot = absRoot
	wc.fs = fs
	wc.fileAPI.fs = fs
	return nil
}

func expandAbsolutePath(scanRoot string, paths []string) []string {
	var locations []string
	for _, l := range paths {
		locations = append(locations, filepath.Join(scanRoot, l))
	}
	return locations
}

func expandAllAbsolutePaths(scanRoots []*scalibrfs.ScanRoot) ([]*scalibrfs.ScanRoot, error) {
	var result []*scalibrfs.ScanRoot
	for _, r := range scanRoots {
		abs, err := r.WithAbsolutePath()
		if err != nil {
			return nil, err
		}
		result = append(result, abs)
	}

	return result, nil
}

func stripAllPathPrefixes(paths []string, scanRoots []*scalibrfs.ScanRoot) ([]string, error) {
	if len(scanRoots) > 0 && scanRoots[0].IsVirtual() {
		// We're using a virtual filesystem with no real absolute paths.
		return paths, nil
	}
	result := make([]string, 0, len(paths))
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}

		rp, err := stripFromAtLeastOnePrefix(abs, scanRoots)
		if err != nil {
			return nil, err
		}
		result = append(result, rp)
	}

	return result, nil
}

// stripFromAtLeastOnePrefix returns the path relative to the first prefix it is relative to.
// If the path is not relative to any of the prefixes, an error is returned.
// The path is expected to be absolute.
func stripFromAtLeastOnePrefix(path string, scanRoots []*scalibrfs.ScanRoot) (string, error) {
	for _, r := range scanRoots {
		if !strings.HasPrefix(path, r.Path) {
			continue
		}
		rel, err := filepath.Rel(r.Path, path)
		if err != nil {
			return "", err
		}

		return rel, nil
	}

	return "", ErrNotRelativeToScanRoots
}

func pathStringListToMap(paths []string) map[string]bool {
	result := make(map[string]bool)
	for _, p := range paths {
		result[p] = true
	}
	return result
}

func addErrToMap(errors map[string]error, key string, err error) {
	if prev, ok := errors[key]; !ok {
		errors[key] = err
	} else {
		errors[key] = fmt.Errorf("%w\n%w", prev, err)
	}
}

func errToExtractorStatus(extractors []Extractor, foundInv map[string]bool, errors map[string]error) []*plugin.Status {
	result := make([]*plugin.Status, 0, len(extractors))
	for _, ex := range extractors {
		result = append(result, plugin.StatusFromErr(ex, foundInv[ex.Name()], errors[ex.Name()]))
	}
	return result
}

func (wc *walkContext) printStatus() {
	log.Infof("Status: new inodes: %d, %.1f inodes/s, new extract calls: %d, path: %q\n",
		wc.inodesVisited-wc.lastInodes,
		float64(wc.inodesVisited-wc.lastInodes)/time.Since(wc.lastStatus).Seconds(),
		wc.extractCalls-wc.lastExtracts, wc.currentPath)

	wc.lastStatus = time.Now()
	wc.lastInodes = wc.inodesVisited
	wc.lastExtracts = wc.extractCalls
}

// GetRealPath returns the real absolute path of the file on the scanning host's filesystem.
// If the file is on a virtual filesystem (e.g. a remote container), it is first copied into a
// temporary directory on the scanning host's filesystem. It's up to the caller to delete the
// directory once they're done using it.
func (i *ScanInput) GetRealPath() (string, error) {
	if i.Root != "" {
		return filepath.Join(i.Root, i.Path), nil
	}

	// No scan root set, this is a virtual filesystem.
	// Move the file to the scanning hosts's filesystem.
	dir, err := os.MkdirTemp("", "scalibr-tmp")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "file")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	io.Copy(f, i.Reader)
	return path, nil
}
