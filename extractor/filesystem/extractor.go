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
	"slices"
	"strings"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/internal"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"
)

// Extractor is the filesystem-based inventory extraction plugin, used to extract inventory data
// from the filesystem such as OS and language packages.
type Extractor interface {
	extractor.Extractor
	// FileRequired should return true if the file described by path and mode is
	// relevant for the extractor.
	// Note that the plugin doesn't traverse the filesystem itself but relies on the core
	// library for that.
	FileRequired(path string, mode fs.FileMode) bool
	// Extract extracts inventory data relevant for the extractor from a given file.
	Extract(ctx context.Context, input *ScanInput) ([]*extractor.Inventory, error)
}

// ScanInput describes one file to extract from.
type ScanInput struct {
	// The path of the file to extract, relative to ScanRoot.
	Path string
	// The root directory where the extraction file walking started from.
	ScanRoot string
	Info     fs.FileInfo
	// A reader for accessing contents of the file.
	// Note that the file is closed by the core library, not the plugin.
	Reader io.Reader
	// Stats collector to export stats internally from a plugin.
	Stats stats.Collector
}

// Config stores the config settings for an extraction run.
type Config struct {
	Extractors []Extractor
	ScanRoot   string
	FS         fs.FS
	// Optional: Individual files to extract inventory from. If specified, the
	// extractors will only look at these files during the filesystem traversal.
	// Note that these are not relative to ScanRoot and thus need to be in
	// sub-directories of ScanRoot.
	FilesToExtract []string
	// Optional: Directories that the file system walk should ignore.
	// Note that these are not relative to ScanRoot and thus need to be
	// sub-directories of ScanRoot.
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
}

// Run runs the specified extractors and returns their extraction results,
// as well as info about whether the plugin runs completed successfully.
func Run(ctx context.Context, config *Config) ([]*extractor.Inventory, []*plugin.Status, error) {
	config.FS = os.DirFS(config.ScanRoot)
	return RunFS(ctx, config)
}

// RunFS runs the specified extractors and returns their extraction results,
// as well as info about whether the plugin runs completed successfully.
// scanRoot is the location of fsys.
// This method is for testing, use Run() to avoid confusion with scanRoot vs fsys.
func RunFS(ctx context.Context, config *Config) ([]*extractor.Inventory, []*plugin.Status, error) {
	if len(config.Extractors) == 0 {
		return []*extractor.Inventory{}, []*plugin.Status{}, nil
	}
	start := time.Now()
	scanRoot, err := filepath.Abs(config.ScanRoot)
	if err != nil {
		return nil, nil, err
	}
	filesToExtract, err := stripPathPrefix(config.FilesToExtract, scanRoot)
	if err != nil {
		return nil, nil, err
	}
	dirsToSkip, err := stripPathPrefix(config.DirsToSkip, scanRoot)
	if err != nil {
		return nil, nil, err
	}
	wc := walkContext{
		ctx:            ctx,
		stats:          config.Stats,
		extractors:     config.Extractors,
		fs:             config.FS,
		scanRoot:       scanRoot,
		filesToExtract: filesToExtract,
		dirsToSkip:     pathStringListToMap(dirsToSkip),
		skipDirRegex:   config.SkipDirRegex,
		readSymlinks:   config.ReadSymlinks,
		maxInodes:      config.MaxInodes,
		inodesVisited:  0,

		lastStatus: time.Now(),

		inventory: []*extractor.Inventory{},
		errors:    make(map[string]error),
		foundInv:  make(map[string]bool),

		mapInodes:   make(map[string]int),
		mapExtracts: make(map[string]int),
	}

	if len(wc.filesToExtract) > 0 {
		err = walkIndividualFiles(config.FS, wc.filesToExtract, wc.handleFile)
	} else {
		err = internal.WalkDirUnsorted(config.FS, ".", wc.handleFile)
	}

	log.Infof("End status: %d inodes visited, %d Extract calls, %s elapsed",
		wc.inodesVisited, wc.extractCalls, time.Since(start))
	printAnalyseInodes(&wc)

	return wc.inventory, errToExtractorStatus(config.Extractors, wc.foundInv, wc.errors), err
}

type walkContext struct {
	ctx            context.Context
	stats          stats.Collector
	extractors     []Extractor
	fs             fs.FS
	scanRoot       string
	filesToExtract []string
	dirsToSkip     map[string]bool // Anything under these paths should be skipped.
	skipDirRegex   *regexp.Regexp
	maxInodes      int
	inodesVisited  int

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

	// Data for analytics.
	mapInodes   map[string]int
	mapExtracts map[string]int
}

func walkIndividualFiles(fsys fs.FS, paths []string, fn fs.WalkDirFunc) error {
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
	s, err := fs.Stat(wc.fs, path)
	if err != nil {
		log.Warnf("os.Stat(%s): %v", path, err)
		return nil
	}

	wc.mapInodes[internal.ParentDir(filepath.Dir(path), 3)]++

	for _, ex := range wc.extractors {
		wc.runExtractor(ex, path, s.Mode())
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

func (wc *walkContext) runExtractor(ex Extractor, path string, mode fs.FileMode) {
	if !ex.FileRequired(path, mode) {
		return
	}
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

	wc.mapExtracts[internal.ParentDir(filepath.Dir(path), 3)]++
	wc.extractCalls++

	start := time.Now()
	results, err := ex.Extract(wc.ctx, &ScanInput{
		Path:     path,
		ScanRoot: wc.scanRoot,
		Info:     info,
		Reader:   rc,
		Stats:    wc.stats,
	})
	wc.stats.AfterExtractorRun(ex.Name(), time.Since(start), err)
	if err != nil {
		addErrToMap(wc.errors, ex.Name(), fmt.Errorf("%s: %w", path, err))
	}

	if len(results) > 0 {
		wc.foundInv[ex.Name()] = true
		for _, r := range results {
			r.Extractor = ex
			wc.inventory = append(wc.inventory, r)
		}
	}
}

func stripPathPrefix(paths []string, prefix string) ([]string, error) {
	result := make([]string, 0, len(paths))
	for _, p := range paths {
		// prefix is assumed to already be an absolute path.
		abs, err := filepath.Abs(filepath.FromSlash(p))
		if err != nil {
			return nil, err
		}
		prefix = filepath.FromSlash(prefix)
		if !strings.HasPrefix(abs, prefix) {
			return nil, fmt.Errorf("%q is not in a subdirectory of %q", abs, prefix)
		}
		rel, err := filepath.Rel(prefix, abs)
		if err != nil {
			return nil, err
		}
		rel = filepath.FromSlash(rel)
		result = append(result, rel)
	}
	return result, nil
}

func pathStringListToMap(paths []string) map[string]bool {
	result := make(map[string]bool)
	for _, p := range paths {
		result[filepath.FromSlash(p)] = true
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

func printAnalyseInodes(wc *walkContext) {
	printSizeInformation(wc)

	transitiveInodes := internal.BuildTransitiveMaps(wc.mapInodes)
	transitiveExtracts := internal.BuildTransitiveMaps(wc.mapExtracts)

	dirs := mapToList(wc, transitiveInodes, transitiveExtracts)

	slices.SortFunc(dirs, func(a, b pathCount) int { return b.inodes - a.inodes })

	printTop10(dirs)
}

func printSizeInformation(wc *walkContext) {
	b := 0
	for p := range wc.mapInodes {
		b += len(p) + 4
	}
	for p := range wc.mapExtracts {
		b += len(p) + 4
	}
	log.Infof("Analytics data: %d dirs in mapInodes, %d dirs in mapExtracts, estimated bytes: %d",
		len(wc.mapInodes), len(wc.mapExtracts), b)
}

type pathCount struct {
	path   string
	inodes int
}

func mapToList(wc *walkContext, transitiveInodes, transitiveExtracts map[string]int) []pathCount {
	dirs := make([]pathCount, 0, len(wc.mapInodes))
	for p, inodes := range wc.mapInodes {
		// If the directory contains any Extract calls, filter it out.
		if wc.mapExtracts[p]+transitiveExtracts[p] > 0 {
			continue
		}
		dirs = append(dirs, pathCount{p, inodes + transitiveInodes[p]})
	}

	return dirs
}

func printTop10(dirs []pathCount) {
	out := ""
	for _, d := range dirs[:min(len(dirs), 10)] {
		out += fmt.Sprintf("%9d %s\n", d.inodes, d.path)
	}
	log.Infof("Top 10 directories by number of files without Extract calls:\n%s", out)
}
