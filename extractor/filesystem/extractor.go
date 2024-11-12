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
	FileRequired(path string, stat func() (fs.FileInfo, error)) bool
	// Extract extracts inventory data relevant for the extractor from a given file.
	Extract(ctx context.Context, input *ScanInput) ([]*extractor.Inventory, error)
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
		readSymlinks:      config.ReadSymlinks,
		maxInodes:         config.MaxInodes,
		inodesVisited:     0,
		storeAbsolutePath: config.StoreAbsolutePath,

		lastStatus: time.Now(),

		inventory: []*extractor.Inventory{},
		errors:    make(map[string]error),
		foundInv:  make(map[string]bool),

		requiredDurationPerExtractor: make(map[string]time.Duration),
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
		wc.beforeWalkDir = time.Now()
		err = internal.WalkDirUnsorted(wc.fs, ".", wc.handleFile)
		wc.walkDirDuration += time.Since(wc.beforeWalkDir)

		if config.PrintDurationAnalysis {

			log.Infof("FS extractors:          %6.3f s", time.Since(start).Seconds())
			log.Infof("  walkDirDuration:      %6.3f s", wc.walkDirDuration.Seconds())
			log.Infof("  handleDuration:       %6.3f s", wc.handleDuration.Seconds())
			log.Infof("    filterDuration:     %6.3f s", wc.filterDuration.Seconds())
			log.Infof("    statDuration:       %6.3f s", wc.statDuration.Seconds())
			log.Infof("    FileRequired()")
			log.Infof("      requiredDuration: %6.3f s", wc.requiredDuration.Seconds())
			for k, v := range wc.requiredDurationPerExtractor {
				log.Infof("        FileRequired(%s): %6.3f s", k, v.Seconds())
			}
			log.Infof("    Extract()")
			log.Infof("      openDuration:     %6.3f s", wc.openDuration.Seconds())
			log.Infof("      extractDuration:  %6.3f s", wc.extractDuration.Seconds())
			log.Infof("      storageDuration:  %6.3f s", wc.storageDuration.Seconds())
		}
	}

	log.Infof("End status: %d inodes visited, %d Extract calls, %s elapsed",
		wc.inodesVisited, wc.extractCalls, time.Since(start))

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
	maxInodes         int
	inodesVisited     int
	storeAbsolutePath bool

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

	beforeWalkDir                time.Time
	walkDirDuration              time.Duration
	handleDuration               time.Duration
	statDuration                 time.Duration
	filterDuration               time.Duration
	requiredDuration             time.Duration
	requiredDurationPerExtractor map[string]time.Duration
	openDuration                 time.Duration
	extractDuration              time.Duration
	storageDuration              time.Duration
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
	wc.walkDirDuration += time.Since(wc.beforeWalkDir)
	start := time.Now()
	defer func() {
		wc.handleDuration += time.Since(start)
		wc.beforeWalkDir = time.Now()
	}()

	startFilter := time.Now()

	wc.printStatus(path)

	wc.inodesVisited++
	if wc.maxInodes > 0 && wc.inodesVisited > wc.maxInodes {
		return fmt.Errorf("maxInodes (%d) exceeded", wc.maxInodes)
	}

	wc.stats.AfterInodeVisited(path)
	if wc.ctx.Err() != nil {
		return wc.ctx.Err()
	}
	if fserr != nil {
		if os.IsPermission(fserr) {
			// Permission errors are expected when traversing the entire filesystem.
			log.Debugf("fserr: %v", fserr)
		} else {
			log.Errorf("fserr: %v", fserr)
		}
		return nil
	}
	if d.Type().IsDir() {
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
	wc.filterDuration += time.Since(startFilter)

	statCalled := false
	var info fs.FileInfo
	var statErr error
	lazyStat := func() (fs.FileInfo, error) {
		if !statCalled {
			startStat := time.Now()
			i, err := fs.Stat(wc.fs, path)
			if err != nil {
				log.Warnf("os.Stat(%s): %v", path, err)
			}
			wc.statDuration += time.Since(startStat)
			statCalled = true
			info = i
			statErr = err
		}
		return info, statErr
	}

	for _, ex := range wc.extractors {
		wc.runExtractor(ex, path, lazyStat)
	}
	return nil
}

func (wc *walkContext) shouldSkipDir(path string) bool {
	if _, ok := wc.dirsToSkip[path]; ok {
		return true
	}
	if wc.skipDirRegex != nil {
		return wc.skipDirRegex.MatchString(path)
	}
	return false
}

func (wc *walkContext) runExtractor(ex Extractor, path string, lazyStat func() (fs.FileInfo, error)) {
	startRequired := time.Now()
	required := ex.FileRequired(path, lazyStat)
	wc.requiredDuration += time.Since(startRequired)
	wc.requiredDurationPerExtractor[ex.Name()] += time.Since(startRequired)
	if !required {
		return
	}

	openStart := time.Now()

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

	wc.openDuration += time.Since(openStart)

	wc.extractCalls++

	start := time.Now()
	results, err := ex.Extract(wc.ctx, &ScanInput{
		FS:     wc.fs,
		Path:   path,
		Root:   wc.scanRoot,
		Info:   info,
		Reader: rc,
	})
	wc.extractDuration += time.Since(start)
	wc.stats.AfterExtractorRun(ex.Name(), time.Since(start), err)

	start = time.Now()
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
	wc.storageDuration += time.Since(start)
}

// UpdateScanRoot updates the scan root and the filesystem to use for the filesystem walk.
// currentRoot is expected to be an absolute path.
func (wc *walkContext) UpdateScanRoot(absRoot string, fs scalibrfs.FS) error {
	wc.scanRoot = absRoot
	wc.fs = fs
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

func (wc *walkContext) printStatus(path string) {
	if time.Since(wc.lastStatus) < 2*time.Second {
		return
	}
	log.Infof("Status: new inodes: %d, %.1f inodes/s, new extract calls: %d, path: %q\n",
		wc.inodesVisited-wc.lastInodes,
		float64(wc.inodesVisited-wc.lastInodes)/time.Since(wc.lastStatus).Seconds(),
		wc.extractCalls-wc.lastExtracts, path)
	wc.lastStatus = time.Now()
	wc.lastInodes = wc.inodesVisited
	wc.lastExtracts = wc.extractCalls
}
