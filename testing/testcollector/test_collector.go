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

// Package testcollector provides an implementation of stats.Collector that
// stores recorded metrics for verification in tests.
package testcollector

import "github.com/google/osv-scalibr/stats"

// Collector implements the stats.Collector interface and simply stores metrics
// by path.
type Collector struct {
	stats.NoopCollector
	fileRequiredStats  map[string]*stats.FileRequiredStats
	fileExtractedStats map[string]*stats.FileExtractedStats
}

// New returns a new test Collector with maps initialized.
func New() *Collector {
	return &Collector{
		fileRequiredStats:  make(map[string]*stats.FileRequiredStats),
		fileExtractedStats: make(map[string]*stats.FileExtractedStats),
	}
}

// AfterFileRequired stores the metrics for calls to `FileRequired`.
func (c *Collector) AfterFileRequired(_ string, filestats *stats.FileRequiredStats) {
	c.fileRequiredStats[filestats.Path] = filestats
}

// AfterFileExtracted stores the metrics for calls to `Extract`.
func (c *Collector) AfterFileExtracted(_ string, filestats *stats.FileExtractedStats) {
	c.fileExtractedStats[filestats.Path] = filestats
}

// FileRequiredResult returns the result metric for a given path, if found.
// Otherwise, returns an empty string.
func (c *Collector) FileRequiredResult(path string) stats.FileRequiredResult {
	if filestats, ok := c.fileRequiredStats[path]; ok {
		return filestats.Result
	}
	return ""
}

// FileExtractedResult returns the result metric for a given path, if found.
// Otherwise, returns an empty string.
func (c *Collector) FileExtractedResult(path string) stats.FileExtractedResult {
	if filestats, ok := c.fileExtractedStats[path]; ok {
		return filestats.Result
	}
	return ""
}

// FileExtractedFileSize returns the file size recorded for a given path, if
// found. Otherwise, returns 0.
func (c *Collector) FileExtractedFileSize(path string) int64 {
	if filestats, ok := c.fileExtractedStats[path]; ok {
		return filestats.FileSizeBytes
	}
	return 0
}
