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
	AfterExtractorRun(pluginName string, extractorstats *AfterExtractorStats)
	AfterDetectorRun(name string, runtime time.Duration, err error)
	AfterScan(runtime time.Duration, status *plugin.ScanStatus)

	// AfterResultsExported is called after results have been exported. destination should merely be
	// a category of where the result was written to (e.g. 'file', 'http'), not the precise location.
	AfterResultsExported(destination string, bytes int, err error)

	// AfterFileRequired may be called by individual plugins after the
	// `FileRequired` method is called on a file. This allows plugins to report
	// why a certain file may have been skipped. Note that in general, extractor
	// plugins will not record a metric if a file was skipped because it is deemed
	// completely irrelevant (e.g. the Python extractor will not report that it
	// skipped a JAR file).
	AfterFileRequired(pluginName string, filestats *FileRequiredStats)

	// AfterFileExtracted may be called by individual plugins after a file was seen in
	// the `Extract` method, as opposed to `AfterExtractorRun`, which is called by
	// the filesystem handling code. This allows plugins to report internal state
	// for metric collection.
	AfterFileExtracted(pluginName string, filestats *FileExtractedStats)

	// MaxRSS is called when the scan is finished. It is used to report the maximum resident
	// memory usage of the scan.
	MaxRSS(maxRSS int64)
}

// NoopCollector implements Collector by doing nothing.
type NoopCollector struct{}

// AfterInodeVisited implements Collector by doing nothing.
func (c NoopCollector) AfterInodeVisited(path string) {}

// AfterExtractorRun implements Collector by doing nothing.
func (c NoopCollector) AfterExtractorRun(pluginName string, extractorstats *AfterExtractorStats) {}

// AfterDetectorRun implements Collector by doing nothing.
func (c NoopCollector) AfterDetectorRun(name string, runtime time.Duration, err error) {}

// AfterScan implements Collector by doing nothing.
func (c NoopCollector) AfterScan(runtime time.Duration, status *plugin.ScanStatus) {}

// AfterResultsExported implements Collector by doing nothing.
func (c NoopCollector) AfterResultsExported(destination string, bytes int, err error) {}

// AfterFileRequired implements Collector by doing nothing.
func (c NoopCollector) AfterFileRequired(pluginName string, filestats *FileRequiredStats) {}

// AfterFileExtracted implements Collector by doing nothing.
func (c NoopCollector) AfterFileExtracted(pluginName string, filestats *FileExtractedStats) {}

// MaxRSS implements Collector by doing nothing.
func (c NoopCollector) MaxRSS(maxRSS int64) {}
