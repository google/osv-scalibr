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

// Package cachedir implements an annotator for packages that are in cache directories.
package cachedir

import (
	"context"
	"path/filepath"
	"regexp"

	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the Annotator.
	Name = "vex/cachedir"
)

// patterns to match cache directories
var cacheDirPatterns = []*regexp.Regexp{
	// Linux/Unix-like systems
	regexp.MustCompile(`^/?tmp/`),
	regexp.MustCompile(`^/?home/[^/]+/\.local/share/Trash/`),
	regexp.MustCompile(`^/?home/[^/]+/\.cache/`),
	regexp.MustCompile(`^/?root/\.cache/`),
	regexp.MustCompile(`^/?var/cache/`),

	// macOS
	regexp.MustCompile(`^/?private/tmp/`),
	regexp.MustCompile(`^/?System/Volumes/Data/private/var/tmp/`),
	regexp.MustCompile(`^/?System/Volumes/Data/private/tmp/`),
	regexp.MustCompile(`^/?Users/[^/]+/Library/Caches/`),

	// Windows
	regexp.MustCompile(`(C:/)?Users/[^/]+/AppData/Local/Temp/`),
	regexp.MustCompile(`(C:/)?Windows/Temp/`),
}

// Annotator adds annotations to packages that are in cache directories.
type Annotator struct{}

// New returns a new Annotator.
func New() annotator.Annotator { return &Annotator{} }

// Name of the annotator.
func (Annotator) Name() string { return Name }

// Version of the annotator.
func (Annotator) Version() int { return 0 }

// Requirements of the annotator.
func (Annotator) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// Annotate adds annotations to packages that are in cache directories.
func (Annotator) Annotate(ctx context.Context, input *annotator.ScanInput, results *inventory.Inventory) error {
	for _, pkg := range results.Packages {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		for _, loc := range pkg.Locations {
			if isInsideCacheDir(loc) {
				pkg.ExploitabilitySignals = append(pkg.ExploitabilitySignals, &vex.PackageExploitabilitySignal{
					Plugin:          Name,
					Justification:   vex.ComponentNotPresent,
					MatchesAllVulns: true,
				})
				break
			}
		}
	}
	return nil
}

func isInsideCacheDir(path string) bool {
	path = filepath.ToSlash(path)

	// Check if the absolute path matches any of the known cache directory patterns
	for _, r := range cacheDirPatterns {
		if r.MatchString(path) {
			return true
		}
	}
	return false
}
