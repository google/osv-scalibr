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

// Package stats contains interfaces and utilities relating to the collection of
// statistics from Scalibr.
package stats

import (
	"time"

	"github.com/google/osv-scalibr/plugin"
)

// Collector is a component which is notified when certain events occur. It can be implemented with
// different metric backends to enable monitoring of Scalibr.
type Collector interface {
	AfterInodeVisited(path string)
	AfterExtractorRun(name string, runtime time.Duration, err error)
	AfterDetectorRun(name string, runtime time.Duration, err error)
	AfterScan(runtime time.Duration, status *plugin.ScanStatus)
	// AfterResultsExported is called after results have been exported. destination should merely be
	// a category of where the result was written to (e.g. 'file', 'http'), not the precise location.
	AfterResultsExported(destination string, bytes int, err error)
	AfterFileSeen(pluginName string, filestats *FileStats)
}

// FileStats is a struct containing stats about a file that was extracted. If
// the file was skipped due to an error during extraction, `Error` will be
// populated.
type FileStats struct {
	Path          string
	Error         error
	FileSizeBytes int64
	// For extractors that unarchive a compressed files, this reports the bytes
	// that were opened during the unarchiving process.
	UncompressedBytes int64
}

// NoopCollector implements Collector by doing nothing.
type NoopCollector struct{}

// AfterInodeVisited implements Collector by doing nothing.
func (c NoopCollector) AfterInodeVisited(path string) {}

// AfterExtractorRun implements Collector by doing nothing.
func (c NoopCollector) AfterExtractorRun(name string, runtime time.Duration, err error) {}

// AfterDetectorRun implements Collector by doing nothing.
func (c NoopCollector) AfterDetectorRun(name string, runtime time.Duration, err error) {}

// AfterScan implements Collector by doing nothing.
func (c NoopCollector) AfterScan(runtime time.Duration, status *plugin.ScanStatus) {}

// AfterResultsExported implements Collector by doing nothing.
func (c NoopCollector) AfterResultsExported(destination string, bytes int, err error) {}

// AfterFileSeen implements Collector by doing nothing.
func (c NoopCollector) AfterFileSeen(name string, filestats *FileStats) {}
