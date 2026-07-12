// Copyright 2026 Google LLC
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
	osv "github.com/google/osv-scalibr/extractor/filesystem/osv"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
)

// BuildLocationToPKGsMap sets up a map of package locations (relative to the specified scan root)
// to package pointers from the inventory.
func BuildLocationToPKGsMap(results *inventory.Inventory, scanRoot *scalibrfs.ScanRoot) map[string][]*extractor.Package {
	locationToPKGs := map[string][]*extractor.Package{}

	// Get root prefix to compare absolute package locations with
	rootPrefix := scanRoot.Path
	if !strings.HasSuffix(rootPrefix, "/") {
		rootPrefix += "/"
	}
pkgLoop:
	for _, pkg := range results.Packages {
		if pkg.Location.Descriptor == nil || pkg.Location.Descriptor.File == nil {
			continue
		}
		// Skip packages found by OS extractors since those are not OS duplicates.
		for _, p := range pkg.Plugins {
			if strings.HasPrefix(p, "os/") {
				continue pkgLoop
			}
		}
		for _, loc := range duplicateLocations(pkg, rootPrefix) {
			if prev, ok := locationToPKGs[loc]; ok {
				locationToPKGs[loc] = append(prev, pkg)
			} else {
				locationToPKGs[loc] = []*extractor.Package{pkg}
			}
		}
	}
	return locationToPKGs
}

func duplicateLocations(pkg *extractor.Package, rootPrefix string) []string {
	if _, ok := pkg.Metadata.(osv.DepGroups); ok && len(pkg.Location.Related) == 0 {
		// Packages extracted from lockfiles/manifests frequently only point at the
		// dependency descriptor path. That is not strong enough evidence to claim the
		// package is already provided by an OS package.
		return nil
	}

	loc := pkg.Location.Descriptor.File.Path
	loc = strings.TrimPrefix(loc, rootPrefix)
	return []string{loc}
}
