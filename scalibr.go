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

// Package scalibr provides an interface for running software inventory
// extraction and security finding detection on a machine.
package scalibr

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"slices"
	"time"

	"github.com/gobwas/glob"
	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/artifact/image"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/trace"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/detector/detectorrunner"
	"github.com/google/osv-scalibr/enricher"
	ce "github.com/google/osv-scalibr/enricher/secrets/convert"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	cf "github.com/google/osv-scalibr/extractor/filesystem/secrets/convert"
	"github.com/google/osv-scalibr/extractor/standalone"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
	pl "github.com/google/osv-scalibr/plugin/list"
	"github.com/google/osv-scalibr/result"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/version"
	"go.uber.org/multierr"
)

var (
	errNoScanRoot            = errors.New("no scan root specified")
	errFilesWithSeveralRoots = errors.New("can't extract specific files with several scan roots")
)

// Scanner is the main entry point of the scanner.
type Scanner struct{}

// New creates a new scanner instance.
func New() *Scanner { return &Scanner{} }

// ScanConfig stores the config settings of a scan run such as the plugins to
// use and the dir to consider the root of the scanned system.
type ScanConfig struct {
	Plugins []plugin.Plugin
	// Capabilities that the scanning environment satisfies, e.g. whether there's
	// network access. Some plugins can only run if certain requirements are met.
	Capabilities *plugin.Capabilities
	// ScanRoots contain the list of root dir used by file walking during extraction.
	// All extractors and detectors will assume files are relative to these dirs.
	// Example use case: Scanning a container image or source code repo that is
	// mounted to a local dir.
	ScanRoots []*scalibrfs.ScanRoot
	// Optional: Individual file or dir paths to extract inventory from. If specified,
	// the extractors will only look at the specified files or at the contents of the
	// specified directories during the filesystem traversal.
	// Note that on real filesystems these are not relative to the ScanRoots and
	// thus need to be in sub-directories of one of the ScanRoots.
	PathsToExtract []string
	// Optional: If true, only the files in the top-level directories in PathsToExtract are
	// extracted and sub-directories are ignored.
	IgnoreSubDirs bool
	// Optional: Directories that the file system walk should ignore.
	// Note that on real filesystems these are not relative to the ScanRoots and
	// thus need to be in sub-directories of one of the ScanRoots.
	// TODO(b/279413691): Also skip local paths, e.g. "Skip all .git dirs"
	DirsToSkip []string
	// Optional: If the regex matches a directory, it will be skipped.
	SkipDirRegex *regexp.Regexp
	// Optional: If the glob matches a directory, it will be skipped.
	SkipDirGlob glob.Glob
	// Optional: Files larger than this size in bytes are skipped. If 0, no limit is applied.
	MaxFileSize int
	// Optional: Skip files declared in .gitignore files in source repos.
	UseGitignore bool
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
	// Optional: If set, this function is called for each file to check if there is a specific
	// extractor for this file. If it returns an extractor, only that extractor is used for the file.
	ExtractorOverride func(filesystem.FileAPI) []filesystem.Extractor
	// Optional: If set, SCALIBR returns an error when a plugin's required plugin
	// isn't configured instead of enabling required plugins automatically.
	ExplicitPlugins bool
}

// EnableRequiredPlugins adds those plugins to the config that are required by enabled
// plugins (such as Detectors or Enrichers) but have not been explicitly enabled.
func (cfg *ScanConfig) EnableRequiredPlugins() error {
	enabledPlugins := map[string]struct{}{}
	for _, e := range cfg.Plugins {
		enabledPlugins[e.Name()] = struct{}{}
	}

	requiredPlugins := map[string]struct{}{}
	for _, p := range cfg.Plugins {
		if d, ok := p.(detector.Detector); ok {
			for _, req := range d.RequiredExtractors() {
				requiredPlugins[req] = struct{}{}
			}
		}
		if e, ok := p.(enricher.Enricher); ok {
			for _, req := range e.RequiredPlugins() {
				requiredPlugins[req] = struct{}{}
			}
		}
	}

	for p := range requiredPlugins {
		if _, enabled := enabledPlugins[p]; enabled {
			continue
		}
		if cfg.ExplicitPlugins {
			// Plugins need to be explicitly enabled,
			// so we log an error instead of auto-enabling them.
			return fmt.Errorf("required plugin %q not enabled", p)
		}

		requiredPlugin, err := pl.FromName(p)
		// TODO: b/416106602 - Implement transitive enablement for required enrichers.
		if err != nil {
			return fmt.Errorf("required plugin %q not present in any list.go: %w", p, err)
		}
		enabledPlugins[p] = struct{}{}
		cfg.Plugins = append(cfg.Plugins, requiredPlugin)
	}
	return nil
}

// ValidatePluginRequirements checks that the scanning environment's capabilities satisfy
// the requirements of all enabled plugin.
func (cfg *ScanConfig) ValidatePluginRequirements() error {
	errs := []error{}
	for _, p := range cfg.Plugins {
		if err := plugin.ValidateRequirements(p, cfg.Capabilities); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// LINT.IfChange

// ScanResult stores the results of a scan incl. scan status and inventory found.
// TODO: b/425645186 - Remove this alias once all callers are migrated to the result package.
type ScanResult = result.ScanResult

// LINT.ThenChange(/binary/proto/scan_result.proto)

// Scan executes the extraction/detection/annotation/etc. plugins using the provided scan config.
func (Scanner) Scan(ctx context.Context, config *ScanConfig) (sr *ScanResult) {
	if config.Stats == nil {
		config.Stats = stats.NoopCollector{}
	}
	defer func() {
		config.Stats.AfterScan(time.Since(sr.StartTime), sr.Status)
	}()
	sro := &newScanResultOptions{
		StartTime: time.Now(),
	}
	if err := config.EnableRequiredPlugins(); err != nil {
		sro.Err = err
	} else if err := config.ValidatePluginRequirements(); err != nil {
		sro.Err = err
	} else if len(config.ScanRoots) == 0 {
		sro.Err = errNoScanRoot
	} else if len(config.PathsToExtract) > 0 && len(config.ScanRoots) > 1 {
		sro.Err = errFilesWithSeveralRoots
	}
	if sro.Err != nil {
		sro.EndTime = time.Now()
		return newScanResult(sro)
	}
	extractors := pl.FilesystemExtractors(config.Plugins)
	extractors, err := cf.SetupVelesExtractors(extractors)
	if err != nil {
		sro.Err = multierr.Append(sro.Err, err)
		sro.EndTime = time.Now()
		return newScanResult(sro)
	}
	extractorConfig := &filesystem.Config{
		Stats:                 config.Stats,
		ReadSymlinks:          config.ReadSymlinks,
		Extractors:            extractors,
		PathsToExtract:        config.PathsToExtract,
		IgnoreSubDirs:         config.IgnoreSubDirs,
		DirsToSkip:            config.DirsToSkip,
		SkipDirRegex:          config.SkipDirRegex,
		MaxFileSize:           config.MaxFileSize,
		SkipDirGlob:           config.SkipDirGlob,
		UseGitignore:          config.UseGitignore,
		ScanRoots:             config.ScanRoots,
		MaxInodes:             config.MaxInodes,
		StoreAbsolutePath:     config.StoreAbsolutePath,
		PrintDurationAnalysis: config.PrintDurationAnalysis,
		ErrorOnFSErrors:       config.ErrorOnFSErrors,
		ExtractorOverride:     config.ExtractorOverride,
	}
	inv, extractorStatus, err := filesystem.Run(ctx, extractorConfig)
	if err != nil {
		sro.Err = err
		sro.EndTime = time.Now()
		return newScanResult(sro)
	}

	sro.Inventory = inv
	// Defer cleanup of all temporary files and directories created during extraction.
	// This function iterates over all EmbeddedFS entries in the inventory and
	// removes their associated TempPaths.
	// Any failures during removal are logged but do not interrupt execution.
	defer func() {
		for _, embeddedFS := range sro.Inventory.EmbeddedFSs {
			for _, tmpPath := range embeddedFS.TempPaths {
				if err := os.RemoveAll(tmpPath); err != nil {
					log.Infof("Failed to remove %s", tmpPath)
				}
			}
		}
	}()
	sro.PluginStatus = append(sro.PluginStatus, extractorStatus...)
	sysroot := config.ScanRoots[0]
	standaloneCfg := &standalone.Config{
		Extractors: pl.StandaloneExtractors(config.Plugins),
		ScanRoot:   &scalibrfs.ScanRoot{FS: sysroot.FS, Path: sysroot.Path},
	}
	standaloneInv, standaloneStatus, err := standalone.Run(ctx, standaloneCfg)
	if err != nil {
		sro.Err = err
		sro.EndTime = time.Now()
		return newScanResult(sro)
	}

	sro.Inventory.Append(standaloneInv)
	sro.PluginStatus = append(sro.PluginStatus, standaloneStatus...)

	px, err := packageindex.New(sro.Inventory.Packages)
	if err != nil {
		sro.Err = err
		sro.EndTime = time.Now()
		return newScanResult(sro)
	}

	findings, detectorStatus, err := detectorrunner.Run(
		ctx, config.Stats, pl.Detectors(config.Plugins), &scalibrfs.ScanRoot{FS: sysroot.FS, Path: sysroot.Path}, px,
	)
	sro.Inventory.PackageVulns = findings.PackageVulns
	sro.Inventory.GenericFindings = findings.GenericFindings
	sro.PluginStatus = append(sro.PluginStatus, detectorStatus...)
	if err != nil {
		sro.Err = err
	}

	annotatorCfg := &annotator.Config{
		Annotators: pl.Annotators(config.Plugins),
		ScanRoot:   sysroot,
	}
	annotatorStatus, err := annotator.Run(ctx, annotatorCfg, &sro.Inventory)
	sro.PluginStatus = append(sro.PluginStatus, annotatorStatus...)
	if err != nil {
		sro.Err = multierr.Append(sro.Err, err)
	}

	enrichers := pl.Enrichers(config.Plugins)
	enrichers, err = ce.SetupVelesEnrichers(enrichers)
	if err != nil {
		sro.Err = multierr.Append(sro.Err, err)
		sro.EndTime = time.Now()
		return newScanResult(sro)
	}
	enricherCfg := &enricher.Config{
		Enrichers: enrichers,
		ScanRoot: &scalibrfs.ScanRoot{
			FS:   sysroot.FS,
			Path: sysroot.Path,
		},
	}
	enricherStatus, err := enricher.Run(ctx, enricherCfg, &sro.Inventory)
	sro.PluginStatus = append(sro.PluginStatus, enricherStatus...)
	if err != nil {
		sro.Err = multierr.Append(sro.Err, err)
	}

	sro.EndTime = time.Now()
	return newScanResult(sro)
}

// ScanContainer scans the provided container image for packages and security findings using the
// provided scan config. It populates the LayerDetails field of the packages with the origin layer
// details. Functions to create an Image from a tarball, remote name, or v1.Image are available in
// the artifact/image/layerscanning/image package.
func (s Scanner) ScanContainer(ctx context.Context, img image.Image, config *ScanConfig) (sr *ScanResult, err error) {
	if len(config.ScanRoots) > 0 {
		log.Warnf("expected no scan roots, but got %d scan roots, overwriting with container image scan root", len(config.ScanRoots))
	}

	imagefs := img.FS()
	// Overwrite the scan roots with the chain layer filesystem.
	config.ScanRoots = []*scalibrfs.ScanRoot{
		{
			FS: imagefs,
		},
	}

	storeAbsPath := config.StoreAbsolutePath
	// Don't try and store absolute path because on windows it will turn unix paths into
	// Windows paths.
	config.StoreAbsolutePath = false

	// Suppress running enrichers until after layer details are populated.
	var enrichers []enricher.Enricher
	var nonEnricherPlugins []plugin.Plugin

	for _, p := range config.Plugins {
		if e, ok := p.(enricher.Enricher); ok {
			enrichers = append(enrichers, e)
		} else {
			nonEnricherPlugins = append(nonEnricherPlugins, p)
		}
	}
	config.Plugins = nonEnricherPlugins

	chainLayers, err := img.ChainLayers()
	if err != nil {
		return nil, fmt.Errorf("failed to get chain layers: %w", err)
	}

	scanResult := s.Scan(ctx, config)
	extractors := pl.FilesystemExtractors(config.Plugins)
	extractors, err = cf.SetupVelesExtractors(extractors)
	if err != nil {
		return scanResult, err
	}
	extractorConfig := &filesystem.Config{
		Stats:                 config.Stats,
		ReadSymlinks:          config.ReadSymlinks,
		Extractors:            extractors,
		PathsToExtract:        config.PathsToExtract,
		IgnoreSubDirs:         config.IgnoreSubDirs,
		DirsToSkip:            config.DirsToSkip,
		SkipDirRegex:          config.SkipDirRegex,
		MaxFileSize:           config.MaxFileSize,
		SkipDirGlob:           config.SkipDirGlob,
		UseGitignore:          config.UseGitignore,
		ScanRoots:             config.ScanRoots,
		MaxInodes:             config.MaxInodes,
		StoreAbsolutePath:     config.StoreAbsolutePath,
		PrintDurationAnalysis: config.PrintDurationAnalysis,
		ErrorOnFSErrors:       config.ErrorOnFSErrors,
		ExtractorOverride:     config.ExtractorOverride,
	}

	// Populate the LayerDetails field of the inventory by tracing the layer origins.
	trace.PopulateLayerDetails(ctx, &scanResult.Inventory, chainLayers, pl.FilesystemExtractors(config.Plugins), extractorConfig)

	// Since we skipped storing absolute path in the main Scan function.
	// Actually convert it to absolute path here.
	if storeAbsPath {
		for _, pkg := range scanResult.Inventory.Packages {
			for i := range pkg.Locations {
				pkg.Locations[i] = "/" + pkg.Locations[i]
			}
		}
	}

	// Run enrichers with the updated inventory.
	enrichers, err = ce.SetupVelesEnrichers(enrichers)
	if err != nil {
		scanResult.Status.Status = plugin.ScanStatusFailed
		scanResult.Status.FailureReason = err.Error()
		return scanResult, nil //nolint:nilerr // Errors are returned in the scanResult.
	}
	enricherCfg := &enricher.Config{
		Enrichers: enrichers,
		ScanRoot: &scalibrfs.ScanRoot{
			FS: imagefs,
		},
	}
	enricherStatus, err := enricher.Run(ctx, enricherCfg, &scanResult.Inventory)
	scanResult.PluginStatus = append(scanResult.PluginStatus, enricherStatus...)
	if err != nil {
		scanResult.Status.Status = plugin.ScanStatusFailed
		scanResult.Status.FailureReason = err.Error()
	}

	// Keep the img variable alive till the end incase cleanup is not called on the parent.
	runtime.KeepAlive(img)

	return scanResult, nil
}

type newScanResultOptions struct {
	StartTime    time.Time
	EndTime      time.Time
	PluginStatus []*plugin.Status
	Inventory    inventory.Inventory
	Err          error
}

func newScanResult(o *newScanResultOptions) *ScanResult {
	status := &plugin.ScanStatus{}
	if o.Err != nil {
		status.Status = plugin.ScanStatusFailed
		status.FailureReason = o.Err.Error()
	} else {
		status.Status = plugin.ScanStatusSucceeded
		// If any plugin failed, set the overall scan status to partially succeeded.
		for _, pluginStatus := range o.PluginStatus {
			if pluginStatus.Status.Status == plugin.ScanStatusFailed {
				status.Status = plugin.ScanStatusPartiallySucceeded
				status.FailureReason = "not all plugins succeeded, see the plugin statuses"
				break
			}
		}
	}
	r := &ScanResult{
		StartTime:    o.StartTime,
		EndTime:      o.EndTime,
		Version:      version.ScannerVersion,
		Status:       status,
		PluginStatus: o.PluginStatus,
		Inventory:    o.Inventory,
	}

	// Sort results for better diffing.
	sortResults(r)
	return r
}

// sortResults sorts the result to make the output deterministic and diffable.
func sortResults(results *ScanResult) {
	slices.SortFunc(results.PluginStatus, cmpStatus)
	slices.SortFunc(results.Inventory.Packages, CmpPackages)
	slices.SortFunc(results.Inventory.PackageVulns, cmpPackageVulns)
	slices.SortFunc(results.Inventory.GenericFindings, cmpGenericFindings)
}

// CmpPackages is a comparison helper fun to be used for sorting Package structs.
func CmpPackages(a, b *extractor.Package) int {
	res := cmp.Or(
		cmp.Compare(a.Name, b.Name),
		cmp.Compare(a.Version, b.Version),
		cmp.Compare(len(a.Plugins), len(b.Plugins)),
	)
	if res != 0 {
		return res
	}

	res = 0
	for i := range a.Plugins {
		res = cmp.Or(res, cmp.Compare(a.Plugins[i], b.Plugins[i]))
	}
	if res != 0 {
		return res
	}

	aloc := fmt.Sprintf("%v", a.Locations)
	bloc := fmt.Sprintf("%v", b.Locations)
	return cmp.Compare(aloc, bloc)
}

func cmpStatus(a, b *plugin.Status) int {
	return cmpString(a.Name, b.Name)
}

func cmpPackageVulns(a, b *inventory.PackageVuln) int {
	return cmpString(a.ID, b.ID)
}

func cmpGenericFindings(a, b *inventory.GenericFinding) int {
	if a.Adv.ID.Reference != b.Adv.ID.Reference {
		return cmpString(a.Adv.ID.Reference, b.Adv.ID.Reference)
	}
	return cmpString(a.Target.Extra, b.Target.Extra)
}

func cmpString(a, b string) int {
	if a < b {
		return -1
	} else if a > b {
		return 1
	}
	return 0
}
