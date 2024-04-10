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
