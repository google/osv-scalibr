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

// Package scalibr provides an interface for running software inventory
// extraction and security finding detection on a machine.
package scalibr

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"time"

	"github.com/gobwas/glob"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/trace"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/inventoryindex"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"

	el "github.com/google/osv-scalibr/extractor/filesystem/list"
	sl "github.com/google/osv-scalibr/extractor/standalone/list"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

var (
	errNoScanRoot            = fmt.Errorf("no scan root specified")
	errFilesWithSeveralRoots = fmt.Errorf("can't extract specific files with several scan roots")
)

// Scanner is the main entry point of the scanner.
type Scanner struct{}

// New creates a new scanner instance.
func New() *Scanner { return &Scanner{} }

// ScanConfig stores the config settings of a scan run such as the plugins to
// use and the dir to consider the root of the scanned system.
type ScanConfig struct {
	FilesystemExtractors []filesystem.Extractor
	StandaloneExtractors []standalone.Extractor
	Detectors            []detector.Detector
	// Capabilities that the scanning environment satisfies, e.g. whether there's
	// network access. Some plugins can only run if certain requirements are met.
	Capabilities *plugin.Capabilities
	// ScanRoots contain the list of root dir used by file walking during extraction.
	// All extractors and detectors will assume files are relative to these dirs.
	// Example use case: Scanning a container image or source code repo that is
	// mounted to a local dir.
	ScanRoots []*scalibrfs.ScanRoot
	// Optional: Individual files to extract inventory from. If specified, the
	// extractors will only look at these files during the filesystem traversal.
	// Note that on real filesystems these are not relative to the ScanRoots and
	// thus need to be in sub-directories of one of the ScanRoots.
	FilesToExtract []string
	// Optional: Directories that the file system walk should ignore.
	// Note that on real filesystems these are not relative to the ScanRoots and
	// thus need to be in sub-directories of one of the ScanRoots.
	// TODO(b/279413691): Also skip local paths, e.g. "Skip all .git dirs"
	DirsToSkip []string
	// Optional: If the regex matches a directory, it will be skipped.
	SkipDirRegex *regexp.Regexp
	// Optional: If the glob matches a directory, it will be skipped.
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

// EnableRequiredExtractors adds those extractors to the config that are required by enabled
// detectors but have not been explicitly enabled.
func (cfg *ScanConfig) EnableRequiredExtractors() error {
	enabledExtractors := map[string]struct{}{}
	for _, e := range cfg.FilesystemExtractors {
		enabledExtractors[e.Name()] = struct{}{}
	}
	for _, e := range cfg.StandaloneExtractors {
		enabledExtractors[e.Name()] = struct{}{}
	}
	for _, d := range cfg.Detectors {
		for _, e := range d.RequiredExtractors() {
			if _, enabled := enabledExtractors[e]; enabled {
				continue
			}
			ex, err := el.ExtractorFromName(e)
			stex, sterr := sl.ExtractorFromName(e)
			if err != nil && sterr != nil {
				return fmt.Errorf("required extractor %q not present in list.go: %w, %w", e, err, sterr)
			}
			enabledExtractors[e] = struct{}{}
			if err == nil {
				cfg.FilesystemExtractors = append(cfg.FilesystemExtractors, ex)
			}
			if sterr == nil {
				cfg.StandaloneExtractors = append(cfg.StandaloneExtractors, stex)
			}
		}
	}
	return nil
}

// ValidatePluginRequirements checks that the scanning environment's capabilities satisfy
// the requirements of all enabled plugin.
func (cfg *ScanConfig) ValidatePluginRequirements() error {
	plugins := make([]plugin.Plugin, 0, len(cfg.FilesystemExtractors)+len(cfg.StandaloneExtractors)+len(cfg.Detectors))
	for _, p := range cfg.FilesystemExtractors {
		plugins = append(plugins, p)
	}
	for _, p := range cfg.StandaloneExtractors {
		plugins = append(plugins, p)
	}
	for _, p := range cfg.Detectors {
		plugins = append(plugins, p)
	}
	errs := []error{}
	for _, p := range plugins {
		if err := plugin.ValidateRequirements(p, cfg.Capabilities); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// LINT.IfChange

// ScanResult stores the software inventory and security findings that a scan run found.
type ScanResult struct {
	Version   string
	StartTime time.Time
	EndTime   time.Time
	// Status of the overall scan.
	Status *plugin.ScanStatus
	// Status and versions of the inventory+vuln plugins that ran.
	PluginStatus []*plugin.Status
	Inventories  []*extractor.Inventory
	Findings     []*detector.Finding
}

// LINT.ThenChange(/binary/proto/scan_result.proto)

// Scan executes the extraction and detection using the provided scan config.
func (Scanner) Scan(ctx context.Context, config *ScanConfig) (sr *ScanResult) {
	if config.Stats == nil {
		config.Stats = stats.NoopCollector{}
	}
	defer func() {
		config.Stats.AfterScan(time.Since(sr.StartTime), sr.Status)
	}()
	sro := &newScanResultOptions{
		StartTime:   time.Now(),
		Inventories: []*extractor.Inventory{},
		Findings:    []*detector.Finding{},
	}
	if err := config.EnableRequiredExtractors(); err != nil {
		sro.Err = err
	} else if err := config.ValidatePluginRequirements(); err != nil {
		sro.Err = err
	} else if len(config.ScanRoots) == 0 {
		sro.Err = errNoScanRoot
	} else if len(config.FilesToExtract) > 0 && len(config.ScanRoots) > 1 {
		sro.Err = errFilesWithSeveralRoots
	}
	if sro.Err != nil {
		sro.EndTime = time.Now()
		return newScanResult(sro)
	}
	extractorConfig := &filesystem.Config{
		Stats:                 config.Stats,
		ReadSymlinks:          config.ReadSymlinks,
		Extractors:            config.FilesystemExtractors,
		FilesToExtract:        config.FilesToExtract,
		DirsToSkip:            config.DirsToSkip,
		SkipDirRegex:          config.SkipDirRegex,
		SkipDirGlob:           config.SkipDirGlob,
		ScanRoots:             config.ScanRoots,
		MaxInodes:             config.MaxInodes,
		StoreAbsolutePath:     config.StoreAbsolutePath,
		PrintDurationAnalysis: config.PrintDurationAnalysis,
		ErrorOnFSErrors:       config.ErrorOnFSErrors,
	}
	inventories, extractorStatus, err := filesystem.Run(ctx, extractorConfig)
	if err != nil {
		sro.Err = err
		sro.EndTime = time.Now()
		return newScanResult(sro)
	}

	sro.Inventories = inventories
	sro.ExtractorStatus = extractorStatus
	sysroot := config.ScanRoots[0]
	standaloneCfg := &standalone.Config{
		Extractors: config.StandaloneExtractors,
		ScanRoot:   &scalibrfs.ScanRoot{FS: sysroot.FS, Path: sysroot.Path},
	}
	standaloneInv, standaloneStatus, err := standalone.Run(ctx, standaloneCfg)
	if err != nil {
		sro.Err = err
		sro.EndTime = time.Now()
		return newScanResult(sro)
	}

	sro.Inventories = append(sro.Inventories, standaloneInv...)
	sro.ExtractorStatus = append(sro.ExtractorStatus, standaloneStatus...)

	ix, err := inventoryindex.New(sro.Inventories)
	if err != nil {
		sro.Err = err
		sro.EndTime = time.Now()
		return newScanResult(sro)
	}

	findings, detectorStatus, err := detector.Run(
		ctx, config.Stats, config.Detectors, &scalibrfs.ScanRoot{FS: sysroot.FS, Path: sysroot.Path}, ix,
	)
	sro.Findings = findings
	sro.DetectorStatus = detectorStatus
	if err != nil {
		sro.Err = err
	}

	sro.EndTime = time.Now()
	return newScanResult(sro)
}

// ScanContainer scans the provided container image for inventory and security findings using the
// provided scan config. It populates the LayerDetails field of the inventory with the origin layer
// details. Functions to create an Image from a tarball, remote name, or v1.Image are available in
// the artifact/image/layerscanning/image package.
func (s Scanner) ScanContainer(ctx context.Context, img *image.Image, config *ScanConfig) (sr *ScanResult, err error) {
	defer img.CleanUp()

	chainLayers, err := img.ChainLayers()
	if err != nil {
		return nil, fmt.Errorf("failed to get chain layers: %w", err)
	}

	if len(chainLayers) == 0 {
		return nil, fmt.Errorf("no chain layers found")
	}

	finalChainLayer := chainLayers[len(chainLayers)-1]
	chainfs := finalChainLayer.FS()

	if config.ScanRoots != nil && len(config.ScanRoots) > 0 {
		log.Warnf("expected no scan roots, but got %d scan roots, overwriting with container image scan root", len(config.ScanRoots))
	}
	// Overwrite the scan roots with the chain layer filesystem.
	config.ScanRoots = []*scalibrfs.ScanRoot{
		&scalibrfs.ScanRoot{
			FS: chainfs,
		},
	}

	scanResult := s.Scan(ctx, config)
	inventory := scanResult.Inventories
	extractorConfig := &filesystem.Config{
		Stats:                 config.Stats,
		ReadSymlinks:          config.ReadSymlinks,
		Extractors:            config.FilesystemExtractors,
		FilesToExtract:        config.FilesToExtract,
		DirsToSkip:            config.DirsToSkip,
		SkipDirRegex:          config.SkipDirRegex,
		SkipDirGlob:           config.SkipDirGlob,
		ScanRoots:             config.ScanRoots,
		MaxInodes:             config.MaxInodes,
		StoreAbsolutePath:     config.StoreAbsolutePath,
		PrintDurationAnalysis: config.PrintDurationAnalysis,
	}

	// Populate the LayerDetails field of the inventory by tracing the layer origins.
	trace.PopulateLayerDetails(ctx, inventory, chainLayers, extractorConfig)
	return scanResult, nil
}

type newScanResultOptions struct {
	StartTime       time.Time
	EndTime         time.Time
	ExtractorStatus []*plugin.Status
	Inventories     []*extractor.Inventory
	DetectorStatus  []*plugin.Status
	Findings        []*detector.Finding
	Err             error
}

func newScanResult(o *newScanResultOptions) *ScanResult {
	status := &plugin.ScanStatus{}
	if o.Err != nil {
		status.Status = plugin.ScanStatusFailed
		status.FailureReason = o.Err.Error()
	} else {
		status.Status = plugin.ScanStatusSucceeded
	}
	r := &ScanResult{
		StartTime:    o.StartTime,
		EndTime:      o.EndTime,
		Status:       status,
		PluginStatus: append(o.ExtractorStatus, o.DetectorStatus...),
		Inventories:  o.Inventories,
		Findings:     o.Findings,
	}

	// Sort results for better diffing.
	sortResults(r)
	return r
}

func hasFailedPlugins(statuses []*plugin.Status) bool {
	for _, s := range statuses {
		if s.Status.Status != plugin.ScanStatusSucceeded {
			return true
		}
	}
	return false
}

// sortResults sorts the result to make the output deterministic and diffable.
func sortResults(results *ScanResult) {
	for _, inventory := range results.Inventories {
		sort.Strings(inventory.Locations)
	}

	slices.SortFunc(results.PluginStatus, cmpStatus)
	slices.SortFunc(results.Inventories, CmpInventories)
	slices.SortFunc(results.Findings, cmpFindings)
}

// CmpInventories is a comparison helper fun to be used for sorting Inventory structs.
func CmpInventories(a, b *extractor.Inventory) int {
	res := cmp.Or(
		cmp.Compare(a.Name, b.Name),
		cmp.Compare(a.Version, b.Version),
		cmp.Compare(a.Extractor.Name(), b.Extractor.Name()),
	)
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

func cmpFindings(a, b *detector.Finding) int {
	if a.Adv.ID.Reference != b.Adv.ID.Reference {
		return cmpString(a.Adv.ID.Reference, b.Adv.ID.Reference)
	}
	return cmpString(a.Extra, b.Extra)
}

func cmpString(a, b string) int {
	if a < b {
		return -1
	} else if a > b {
		return 1
	}
	return 0
}
