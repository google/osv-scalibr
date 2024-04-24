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
	"context"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"time"

	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventoryindex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"
)

// Scanner is the main entry point of the scanner.
type Scanner struct{}

// New creates a new scanner instance.
func New() *Scanner { return &Scanner{} }

// ScanConfig stores the config settings of a scan run such as the plugins to
// use and the dir to consider the root of the scanned system.
type ScanConfig struct {
	InventoryExtractors []extractor.InventoryExtractor
	Detectors           []detector.Detector
	ScanRoot            string
	// Directories that the file system walk should ignore, relative to the FS root.
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
	extractorConfig := &extractor.Config{
		Stats:        config.Stats,
		ReadSymlinks: config.ReadSymlinks,
		Extractors:   config.InventoryExtractors,
		DirsToSkip:   config.DirsToSkip,
		SkipDirRegex: config.SkipDirRegex,
		ScanRoot:     config.ScanRoot,
		MaxInodes:    config.MaxInodes,
	}
	inventories, extractorStatus, err := extractor.Run(ctx, extractorConfig)
	sro.Inventories = inventories
	sro.ExtractorStatus = extractorStatus
	if err != nil {
		sro.Err = err
		sro.EndTime = time.Now()
		return newScanResult(sro)
	}

	ix, err := inventoryindex.New(inventories)
	if err != nil {
		sro.Err = err
		sro.EndTime = time.Now()
		return newScanResult(sro)
	}

	findings, detectorStatus, err := detector.Run(ctx, config.Stats, config.Detectors, config.ScanRoot, ix)
	sro.Findings = findings
	sro.DetectorStatus = detectorStatus
	if err != nil {
		sro.Err = err
	}

	sro.EndTime = time.Now()
	return newScanResult(sro)
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
	slices.SortFunc(results.Inventories, cmpInventories)
	slices.SortFunc(results.Findings, cmpFindings)
}

func cmpInventories(a, b *extractor.Inventory) int {
	aloc := fmt.Sprintf("%v", a.Locations)
	bloc := fmt.Sprintf("%v", b.Locations)
	if aloc != bloc {
		return cmpString(aloc, bloc)
	}
	if a.Name != b.Name {
		return cmpString(a.Name, b.Name)
	}
	if a.Version != b.Version {
		return cmpString(a.Version, b.Version)
	}
	if a.Extractor != b.Extractor {
		return cmpString(a.Extractor, b.Extractor)
	}
	return 0
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
