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

package internal

import (
	"context"
	"errors"
	"fmt"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
)

// OfflineEnricher uses an [OfflineSolver] to link direct dependencies present in the inventory.
//
// This is intended as a base for implementing SCALIBR enricher plugins. You may either use the
// provided [Enrich] method, or perform additional pre/post-processing on the inventory,
// as needed by the specific application.
type OfflineEnricher struct {
	pkgExtractor PackageExtractor[*extractor.Package]
}

// NewOfflineEnricher creates a new [OfflineEnricher], using the given [PackageExtractor].
func NewOfflineEnricher(pkgExtractor PackageExtractor[*extractor.Package]) OfflineEnricher {
	return OfflineEnricher{
		pkgExtractor: pkgExtractor,
	}
}

// Enrich traverses the inventory to link direct dependencies present in the artifact.
func (e *OfflineEnricher) Enrich(ctx context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	solver, err := NewOfflineSolver(inv.Packages, e.pkgExtractor)
	if err != nil {
		return fmt.Errorf("failed to create dependency solver: %w", err)
	}

	for _, parent := range inv.Packages {
		reqs, err := solver.Requirements(ctx, parent)
		if errors.Is(err, resolve.ErrNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to fetch requirements for %s: %w", parent.Name, err)
		}
		if len(reqs) == 0 {
			continue
		}

		parentPaths := map[string]bool{}
		for _, rel := range parent.Location.Related {
			if path := rel.PathOrEmpty(); path != "" {
				parentPaths[path] = true
			}
		}

		for _, req := range reqs {
			children, err := solver.Solve(ctx, req)
			if err != nil {
				return fmt.Errorf("failed to solve %s: %w", parent.Name, err)
			}
			for _, child := range filterPathRelations(parentPaths, children) {
				parentID, err := parent.RequireID()
				if err != nil {
					return fmt.Errorf("failed to generate ID for %s: %w", parent.Name, err)
				}
				if child.ParentIDs == nil {
					child.ParentIDs = make(map[string]bool)
				}
				child.ParentIDs[parentID] = true
			}
		}
	}

	return nil
}

func filterPathRelations(parentPaths map[string]bool, children []*extractor.Package) []*extractor.Package {
	var filtered []*extractor.Package
	for _, child := range children {
		for _, childRel := range child.Location.Related {
			if childPath := childRel.PathOrEmpty(); childPath != "" {
				if _, found := parentPaths[childPath]; found {
					filtered = append(filtered, child)
					break
				}
			}
		}
	}
	if len(filtered) == 0 {
		return children
	}
	return filtered
}
