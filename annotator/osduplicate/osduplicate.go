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

// Package osduplicate implements utility functions for identifying inventory duplicates found in OS packages.
package osduplicate

import (
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
)

// BuildLocationToPKGsMap sets up a map of package locations to package pointers from the inventory.
func BuildLocationToPKGsMap(results *inventory.Inventory) map[string][]*extractor.Package {
	locationToPKGs := map[string][]*extractor.Package{}
pkgLoop:
	for _, pkg := range results.Packages {
		if len(pkg.Locations) == 0 {
			continue
		}
		// Skip packages found by OS extractors since those are not OS duplicates.
		for _, p := range pkg.Plugins {
			if strings.HasPrefix(p, "os/") {
				continue pkgLoop
			}
		}
		// The descriptor file (e.g. lockfile) is always stored in the first element.
		// TODO(b/400910349): Separate locations into a dedicated "descriptor file"
		// and "other files" field.
		loc := pkg.Locations[0]
		if prev, ok := locationToPKGs[loc]; ok {
			locationToPKGs[loc] = append(prev, pkg)
		} else {
			locationToPKGs[loc] = []*extractor.Package{pkg}
		}
	}
	return locationToPKGs
}
