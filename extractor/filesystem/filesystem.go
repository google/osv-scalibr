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

// Package filesystem provides the interface for inventory extraction plugins.
package filesystem

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/gobwas/glob"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/common"
	"github.com/google/osv-scalibr/extractor/filesystem/internal"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"
)

var (
	// ErrNotRelativeToScanRoots is returned when one of the file or directory to be retrieved or
	// skipped is not relative to any of the scan roots.
	ErrNotRelativeToScanRoots = errors.New("path not relative to any of the scan roots")
	// ErrFailedToOpenFile is returned when opening a file fails.
	ErrFailedToOpenFile = errors.New("failed to open file")
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
	Extract(ctx context.Context, input *ScanInput) (inventory.Inventory, error)
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
	PathsToExtract []string
	// Optional: If true, only the files in the top-level directories in PathsToExtract are
	// extracted and sub-directories are ignored.
	IgnoreSubDirs bool
	// Optional: Directories that the file system walk should ignore.
	// Note that these are not relative to the ScanRoots and thus need to be
	// sub-directories of one of the ScanRoots.
	// TODO(b/279413691): Also skip local paths, e.g. "Skip all .git dirs"
	DirsToSkip []string
	// Optional: If the regex matches a directory, it will be skipped.
	SkipDirRegex *regexp.Regexp
	// Optional: If the regex matches a glob, it will be skipped.
	SkipDirGlob glob.Glob
	// Optional: Skip files declared in .gitignore files in source repos.
	UseGitignore bool
	// Optional: stats allows to enter a metric hook. If left nil, no metrics will be recorded.
	Stats stats.Collector
	// Optional: Whether to read symlinks.
	ReadSymlinks bool
	// Optional: Limit for visited inodes. If 0, no limit is applied.
	MaxInodes int
	// Optional: Files larger than this size in bytes are skipped. If 0, no limit is applied.
	MaxFileSize int
	// Optional: By default, inventories stores a path relative to the scan root. If StoreAbsolutePath
	// is set, the absolute path is stored instead.
	StoreAbsolutePath bool
	// Optional: If true, print a detailed analysis of the duration of each extractor.
	PrintDurationAnalysis bool
	// Optional: If true, fail the scan if any permission errors are encountered.
	ErrorOnFSErrors bool
	// Optional: If set, this function is called for each file to check if there is a specific
	// extractor for this file. If it returns an extractor, only that extractor is used for the file.
	ExtractorOverride func(FileAPI) []Extractor
}

// Run runs the specified extractors and returns their extraction results,
// as well as info about whether the plugin runs completed successfully.
func Run(ctx context.Context, config *Config) (inventory.Inventory, []*plugin.Status, error) {
	if len(config.Extractors) == 0 {
		return inventory.Inventory{}, []*plugin.Status{}, nil
	}

	scanRoots, err := expandAllAbsolutePaths(config.ScanRoots)
	if err != nil {
		return inventory.Inventory{}, nil, err
	}

	wc, err := InitWalkContext(ctx, config, scanRoots)
	if err != nil {
		return inventory.Inventory{}, nil, err
	}

	var status []*plugin.Status
	inv := inventory.Inventory{}
	for _, root := range scanRoots {
		newInv, st, err := runOnScanRoot(ctx, config, root, wc)
		if err != nil {
			return inv, nil, err
		}

		inv.Append(newInv)
		status = append(status, st...)
	}

	return inv, status, nil
}

func runOnScanRoot(ctx context.Context, config *Config, scanRoot *scalibrfs.ScanRoot, wc *walkContext) (inventory.Inventory, []*plugin.Status, error) {
	abs := ""
	var err error
	if !scanRoot.IsVirtual() {
		abs, err = filepath.Abs(scanRoot.Path)
		if err != nil {
			return inventory.Inventory{}, nil, err
		}
	}
	if err = wc.UpdateScanRoot(abs, scanRoot.FS); err != nil {
		return inventory.Inventory{}, nil, err
	}

	// Run extractors on the scan root
	inv, status, err := RunFS(ctx, config, wc)
	if err != nil {
		return inv, status, err
	}

	// Process embedded filesystems
	var additionalInv inventory.Inventory
	for _, embeddedFS := range inv.EmbeddedFSs {
		// Mount the embedded filesystem
		mountedFS, err := embeddedFS.GetEmbeddedFS(ctx)
		if err != nil {
			status = append(status, &plugin.Status{
				Name:    "EmbeddedFS",
				Version: 1,
				Status: &plugin.ScanStatus{
					Status:        plugin.ScanStatusFailed,
					FailureReason: fmt.Sprintf("failed to mount embedded filesystem %s: %v", embeddedFS.Path, err),
				},
			})
			continue
		}

		// Create a new ScanRoot for the mounted filesystem
		newScanRoot := &scalibrfs.ScanRoot{
			FS:   mountedFS,
			Path: "", // Virtual filesystem
		}

		// Reuse the existing config, updating only necessary fields
		config.ScanRoots = []*scalibrfs.ScanRoot{newScanRoot}
		// Clear PathsToExtract to scan entire mounted filesystem
		config.PathsToExtract = []string{}

		// Run extractors on the mounted filesystem using Run
		mountedInv, mountedStatus, err := Run(ctx, config)
		if err != nil {
			status = append(status, &plugin.Status{
				Name:    "EmbeddedFS",
				Version: 1,
				Status: &plugin.ScanStatus{
					Status:        plugin.ScanStatusFailed,
					FailureReason: fmt.Sprintf("failed to extract from embedded filesystem %s: %v", embeddedFS.Path, err),
				},
			})
			continue
		}

		// Prepend embeddedFS.Path to Locations for all packages in mountedInv
		for _, pkg := range mountedInv.Packages {
			updatedLocations := make([]string, len(pkg.Locations))
			for i, loc := range pkg.Locations {
				updatedLocations[i] = fmt.Sprintf("%s:%s", embeddedFS.Path, loc)
			}
			pkg.Locations = updatedLocations
		}

		additionalInv.Append(mountedInv)
		status = append(status, mountedStatus...)

		// Collect temporary directories and raw files after traversal for removal.
		if c, ok := mountedFS.(common.CloserWithTmpPaths); ok {
			embeddedFS.TempPaths = c.TempPaths()
		}
	}

	// Combine inventories
	inv.Append(additionalInv)
	return inv, status, nil
}

// InitWalkContext initializes the walk context for a filesystem walk. It strips all the paths that
// are expected to be relative to the scan root.
// This function is exported for TESTS ONLY.
func InitWalkContext(ctx context.Context, config *Config, absScanRoots []*scalibrfs.ScanRoot) (*walkContext, error) {
	pathsToExtract, err := stripAllPathPrefixes(config.PathsToExtract, absScanRoots)
	if err != nil {
		return nil, err
	}
	pathsToExtract = toSlashPaths(pathsToExtract)

	dirsToSkip, err := stripAllPathPrefixes(config.DirsToSkip, absScanRoots)
	if err != nil {
		return nil, err
	}
	dirsToSkip = toSlashPaths(dirsToSkip)

	return &walkContext{
		ctx:               ctx,
		stats:             config.Stats,
		extractors:        config.Extractors,
		pathsToExtract:    pathsToExtract,
		ignoreSubDirs:     config.IgnoreSubDirs,
		dirsToSkip:        pathStringListToMap(dirsToSkip),
		skipDirRegex:      config.SkipDirRegex,
		skipDirGlob:       config.SkipDirGlob,
		useGitignore:      config.UseGitignore,
		readSymlinks:      config.ReadSymlinks,
		maxInodes:         config.MaxInodes,
		maxFileSize:       config.MaxFileSize,
		inodesVisited:     0,
		storeAbsolutePath: config.StoreAbsolutePath,
		errorOnFSErrors:   config.ErrorOnFSErrors,
		extractorOverride: config.ExtractorOverride,

		lastStatus: time.Now(),

		inventory: inventory.Inventory{},
		errors:    make(map[string]error),
		foundInv:  make(map[string]bool),

		fileAPI: &lazyFileAPI{},
	}, nil
}

// RunFS runs the specified extractors and returns their extraction results,
// as well as info about whether the plugin runs completed successfully.
// scanRoot is the location of fsys.
// This method is for testing, use Run() to avoid confusion with scanRoot vs fsys.
func RunFS(ctx context.Context, config *Config, wc *walkContext) (inventory.Inventory, []*plugin.Status, error) {
	start := time.Now()
	if wc == nil || wc.fs == nil {
		return inventory.Inventory{}, nil, errors.New("walk context is nil")
	}

	var err error
	log.Infof("Starting filesystem walk for root: %v", wc.scanRoot)
	if len(wc.pathsToExtract) > 0 {
		err = walkIndividualPaths(wc)
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

		err = internal.WalkDirUnsorted(wc.fs, ".", wc.handleFile, wc.postHandleFile)

		close(quit)
	}

	// On Windows, elapsed and wall time are probably the same. On Linux and Mac they are different,
	// if Scalibr was suspended during runtime.
	log.Infof("End status: %d dirs visited, %d inodes visited, %d Extract calls, %s elapsed, %s wall time",
		wc.dirsVisited, wc.inodesVisited, wc.extractCalls, time.Since(start), time.Duration(time.Now().UnixNano()-start.UnixNano()))

	return wc.inventory, errToExtractorStatus(config.Extractors, wc.foundInv, wc.errors), err
}

type walkContext struct {
	//nolint:containedctx
	ctx               context.Context
	stats             stats.Collector
	extractors        []Extractor
	fs                scalibrfs.FS
	scanRoot          string
	pathsToExtract    []string
	ignoreSubDirs     bool
	dirsToSkip        map[string]bool // Anything under these paths should be skipped.
	skipDirRegex      *regexp.Regexp
	skipDirGlob       glob.Glob
	useGitignore      bool
	maxInodes         int
	inodesVisited     int
	maxFileSize       int // In bytes.
	dirsVisited       int
	storeAbsolutePath bool
	errorOnFSErrors   bool

	// applicable gitignore patterns for the current and parent directories.
	gitignores []internal.GitignorePattern
	// Inventories found.
	inventory inventory.Inventory
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

	// If set, this function is called for each file to check if there is a specific
	// extractor for this file. If it returns an extractor, only that extractor is used for the file.
	extractorOverride func(FileAPI) []Extractor
}

func walkIndividualPaths(wc *walkContext) error {
	for _, p := range wc.pathsToExtract {
		p := filepath.ToSlash(p)
		info, err := fs.Stat(wc.fs, p)
		if err != nil {
			err = wc.handleFile(p, nil, err)
		} else {
			if info.IsDir() {
				// Recursively scan the contents of the directory.
				if wc.useGitignore {
					// Parse parent dir .gitignore files up to the scan root.
					gitignores, err := internal.ParseParentGitignores(wc.fs, p)
					if err != nil {
						return err
					}
					wc.gitignores = gitignores
				}
				err = internal.WalkDirUnsorted(wc.fs, p, wc.handleFile, wc.postHandleFile)
				wc.gitignores = nil
				if err != nil {
					return err
				}
				continue
			}
			err = wc.handleFile(p, fs.FileInfoToDirEntry(info), nil)
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

	wc.fileAPI.currentPath = path
	wc.fileAPI.currentStatCalled = false

	if d.Type().IsDir() {
		wc.dirsVisited++
		if wc.useGitignore {
			gitignores := internal.EmptyGitignore()
			var err error
			if !wc.shouldSkipDir(path) {
				gitignores, err = internal.ParseDirForGitignore(wc.fs, path)
				if err != nil {
					return err
				}
			}
			wc.gitignores = append(wc.gitignores, gitignores)
		}

		exts := wc.extractors
		ignoreFileRequired := false
		// Pass the path to the extractors that extract from directories.
		if wc.extractorOverride != nil {
			if overrideExts := wc.extractorOverride(wc.fileAPI); len(overrideExts) > 0 {
				exts = overrideExts
				ignoreFileRequired = true
			}
		}

		for _, ex := range exts {
			if ex.Requirements().ExtractFromDirs &&
				(ignoreFileRequired || ex.FileRequired(wc.fileAPI)) {
				wc.runExtractor(ex, path, true)
			}
		}

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

	if wc.useGitignore {
		if internal.GitignoreMatch(wc.gitignores, strings.Split(path, "/"), false) {
			return nil
		}
	}

	exts := wc.extractors
	ignoreFileRequired := false
	// Pass the path to the extractors that extract from directories.
	if wc.extractorOverride != nil {
		if overrideExts := wc.extractorOverride(wc.fileAPI); len(overrideExts) > 0 {
			exts = overrideExts
			ignoreFileRequired = true
		}
	}

	fSize := int64(-1) // -1 means we haven't checked the file size yet.
	for _, ex := range exts {
		if !ex.Requirements().ExtractFromDirs &&
			(ignoreFileRequired || ex.FileRequired(wc.fileAPI)) {
			if wc.maxFileSize > 0 && fSize == -1 {
				var err error
				fSize, err = fileSize(wc.fileAPI)
				if err != nil {
					return fmt.Errorf("failed to get file size for %q: %w", path, err)
				}
				if fSize > int64(wc.maxFileSize) {
					log.Debugf("Skipping file %q because it has size %d bytes and the maximum is %d bytes", path, fSize, wc.maxFileSize)
					return nil
				}
			}

			wc.runExtractor(ex, path, false)
		}
	}
	return nil
}

func (wc *walkContext) postHandleFile(path string, d fs.DirEntry) {
	if len(wc.gitignores) > 0 && d.Type().IsDir() {
		// Remove .gitignores that applied to this directory.
		wc.gitignores = wc.gitignores[:len(wc.gitignores)-1]
	}
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
	if wc.ignoreSubDirs && !slices.Contains(wc.pathsToExtract, path) {
		// Skip dirs that aren't one of the root dirs.
		return true
	}
	if wc.useGitignore && internal.GitignoreMatch(wc.gitignores, strings.Split(path, "/"), true) {
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

func (wc *walkContext) runExtractor(ex Extractor, path string, isDir bool) {
	var rc fs.File
	var info fs.FileInfo
	var err error
	if !isDir {
		rc, err = wc.fs.Open(path)
		if err != nil {
			addErrToMap(wc.errors, ex.Name(), fmt.Errorf("Open(%s): %w", path, err))
			return
		}
		defer rc.Close()

		info, err = rc.Stat()
		if err != nil {
			addErrToMap(wc.errors, ex.Name(), fmt.Errorf("stat(%s): %w", path, err))
			return
		}
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
	wc.stats.AfterExtractorRun(ex.Name(), &stats.AfterExtractorStats{
		Path:      path,
		Root:      wc.scanRoot,
		Runtime:   time.Since(start),
		Inventory: &results,
		Error:     err,
	})

	if err != nil {
		addErrToMap(wc.errors, ex.Name(), fmt.Errorf("%s: %w", path, err))
	}

	if !results.IsEmpty() {
		wc.foundInv[ex.Name()] = true
		for _, r := range results.Packages {
			r.Plugins = append(r.Plugins, ex.Name())
			if wc.storeAbsolutePath {
				r.Locations = expandAbsolutePath(wc.scanRoot, r.Locations)
			}
		}
		wc.inventory.Append(results)
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

// toSlashPaths returns a new []string that converts all paths to use /
func toSlashPaths(paths []string) []string {
	returnPaths := make([]string, len(paths))
	for i, s := range paths {
		returnPaths[i] = filepath.ToSlash(s)
	}

	return returnPaths
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
	return scalibrfs.GetRealPath(&scalibrfs.ScanRoot{FS: i.FS, Path: i.Root}, i.Path, i.Reader)
}

// TODO(b/380419487): This list is not exhaustive. We should add more extensions here.
var (
	unlikelyExecutableExtensions = map[string]bool{
		".c":             true,
		".cc":            true,
		".cargo-ok":      true,
		".crate":         true,
		".css":           true,
		".db":            true,
		".gitattributes": true,
		".gitignore":     true,
		".go":            true,
		".h":             true,
		".html":          true,
		".jpg":           true,
		".json":          true,
		".lock":          true,
		".log":           true,
		".md":            true,
		".mod":           true,
		".png":           true,
		".proto":         true,
		".rs":            true,
		".stderr":        true,
		".sum":           true,
		".svg":           true,
		".tar":           true,
		".tmpl":          true,
		".toml":          true,
		".txt":           true,
		".woff2":         true,
		".xml":           true,
		".yaml":          true,
		".yml":           true,
		".zip":           true,
		".ziphash":       true,
	}

	// Always interesting binary extensions
	likelyFileExts = map[string]bool{
		".a": true,
		// Binary extensions
		".bin": true,
		".elf": true,
		".run": true,
		".o":   true,
		// Windows Binary extensions:
		".exe": true,
		".dll": true,

		// Shared library: true extension: true
		".so": true,
		// and .so: true.[number]

		// Script extensions: true
		".py":   true, // Python
		".sh":   true, // bash/sh/zsh
		".bash": true,

		".pl":  true, // Perl
		".rb":  true, // Ruby
		".php": true, // Php
		".awk": true, // Awk
		".tcl": true, // tcl
	}
	likelyFileExtRegexes = map[string]*regexp.Regexp{
		".so.": regexp.MustCompile(`.so.\d+$`),
	}
)

// IsInterestingExecutable returns true if the specified file is an executable which may need scanning.
func IsInterestingExecutable(api FileAPI) bool {
	path := api.Path()
	extension := filepath.Ext(path)
	if unlikelyExecutableExtensions[extension] {
		return false
	}

	if likelyFileExts[extension] {
		return true
	}

	for substrTest, regex := range likelyFileExtRegexes {
		if strings.Contains(path, substrTest) && regex.MatchString(path) {
			return true
		}
	}

	mode, err := api.Stat()
	return err == nil && mode.Mode()&0111 != 0
}

func fileSize(file FileAPI) (int64, error) {
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}
