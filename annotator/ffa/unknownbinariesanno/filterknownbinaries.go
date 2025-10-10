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

// Package unknownbinariesanno removes all packages extracted by unknown binaries
// filters out the known binaries, and records the remaining as a finding.
package unknownbinariesanno

import (
	"context"
	"fmt"
	"slices"

	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/ffa/unknownbinariesanno/internal/apkfilter"
	"github.com/google/osv-scalibr/annotator/ffa/unknownbinariesanno/internal/dpkgfilter"
	"github.com/google/osv-scalibr/annotator/ffa/unknownbinariesanno/internal/filter"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/ffa/unknownbinariesextr"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name of the plugin
const Name = "ffa/unknownbinaries"

// List of filters to apply to exclude known binaries
var filters = []filter.Filter{
	dpkgfilter.DpkgFilter{},
	apkfilter.ApkFilter{},
}

// Annotator further processes the UnknownBinaryExtractor
type Annotator struct {
}

// New returns a new Annotator.
func New() annotator.Annotator {
	return &Annotator{}
}

// Annotate filters out binaries extracted by unknwonbinaries extractor that can be accounted for by other
// inventories or metadata on the FS.
func (anno *Annotator) Annotate(ctx context.Context, input *annotator.ScanInput, inv *inventory.Inventory) error {
	unknownBinariesSet := map[string]*extractor.Package{}
	filteredPackages := make([]*extractor.Package, 0, len(inv.Packages))
	for _, e := range inv.Packages {
		if !slices.Contains(e.Plugins, unknownbinariesextr.Name) {
			filteredPackages = append(filteredPackages, e)
			continue
		}

		unknownBinariesSet[e.Locations[0]] = e
	}

	// First account for all the files we have successfully extracted.
	for _, e := range filteredPackages {
		for _, location := range e.Locations {
			delete(unknownBinariesSet, location)
		}
	}

	// Remove all unknown binary packages from output packages
	inv.Packages = filteredPackages

	// Two sets of filters, one with a hashset that gets elements deleted out of, and another with a simple loop

	// Hash set filter
	for _, f := range filters {
		err := f.HashSetFilter(ctx, input.ScanRoot.FS, unknownBinariesSet)
		if err != nil {
			return fmt.Errorf("%s halted at %q (%q) because %w", anno.Name(), input.ScanRoot.Path, f.Name(), err)
		}
	}

	// Loop Filter
RemainingPathsLoop:
	for p, val := range unknownBinariesSet {
		for _, f := range filters {
			if f.ShouldExclude(ctx, input.ScanRoot.FS, p) {
				continue RemainingPathsLoop
			}
		}

		// TODO(b/400910349): We are currently readding it as packages, but eventually we would want a separate type
		// as this information does not behave like packages.
		inv.Packages = append(inv.Packages, val)
	}

	return nil
}

var _ annotator.Annotator = &Annotator{}

// Name returns the name of the enricher.
func (*Annotator) Name() string {
	return Name
}

// Version returns the version of the enricher.
func (*Annotator) Version() int {
	return 0
}

// Requirements returns the requirements of the enricher.
func (*Annotator) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// RequiredPlugins returns the names of the plugins required by the enricher.
func (*Annotator) RequiredPlugins() []string {
	return []string{unknownbinariesextr.Name}
}
