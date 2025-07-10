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

// Package enricher provides the interface for enrichment plugins.
package enricher

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

var (
	// ErrNoDirectFS is returned when an enricher requires direct filesystem access but the scan root is nil.
	ErrNoDirectFS = errors.New("enrichment requires direct filesystem access but scan root is nil")

	// EnricherOrder describes the order in which specific enrichers need to run in.
	// TODO(b/416106602): Use required enrichers instead of a global ordering list.
	EnricherOrder = []string{
		"reachability/java",
		"vulnmatch/osvdev",
		"vex/filter",
	}
)

// Enricher is the interface for an enrichment plugin, used to enrich scan results with additional
// information through APIs or other sources.
type Enricher interface {
	plugin.Plugin
	// RequiredPlugins returns a list of Plugins that need to be enabled for this Enricher to run.
	RequiredPlugins() []string
	// Enrich enriches the scan results with additional information.
	Enrich(ctx context.Context, input *ScanInput, inv *inventory.Inventory) error
}

// Config for running enrichers.
type Config struct {
	Enrichers []Enricher
	ScanRoot  *scalibrfs.ScanRoot
}

// ScanInput provides information for the enricher about the scan.
type ScanInput struct {
	// The root of the artifact being scanned.
	ScanRoot *scalibrfs.ScanRoot
}

// Run runs the specified enrichers and returns their statuses.
func Run(ctx context.Context, config *Config, inventory *inventory.Inventory) ([]*plugin.Status, error) {
	var statuses []*plugin.Status
	if len(config.Enrichers) == 0 {
		return statuses, nil
	}

	orderEnrichers(config.Enrichers)

	for _, e := range config.Enrichers {
		capabilities := e.Requirements()
		if capabilities != nil && capabilities.DirectFS && config.ScanRoot == nil {
			return nil, fmt.Errorf("%w: for enricher %v", ErrNoDirectFS, e.Name())
		}
	}

	input := &ScanInput{}
	if config.ScanRoot != nil {
		if !config.ScanRoot.IsVirtual() {
			p, err := filepath.Abs(config.ScanRoot.Path)
			if err != nil {
				return nil, err
			}
			config.ScanRoot.Path = p
		}
		input = &ScanInput{
			ScanRoot: config.ScanRoot,
		}
	}

	for _, e := range config.Enrichers {
		err := e.Enrich(ctx, input, inventory)
		// TODO - b/410630503: Support partial success.
		statuses = append(statuses, plugin.StatusFromErr(e, false, err))
	}
	return statuses, nil
}

// Orders the enrichers to make sure they're run in the order specified by EnricherOrder.
func orderEnrichers(enrichers []Enricher) {
	nameToPlace := make(map[string]int)
	for i, name := range EnricherOrder {
		nameToPlace[name] = i
	}
	getPlace := func(name string) int {
		if place, ok := nameToPlace[name]; ok {
			return place
		}
		// Enrichers not in the explicit list can run in any order.
		return len(nameToPlace)
	}

	slices.SortFunc(enrichers, func(a Enricher, b Enricher) int {
		return cmp.Or(
			cmp.Compare(getPlace(a.Name()), getPlace(b.Name())),
			// Use the name as a tie-breaker to keep ordering deterministic.
			strings.Compare(a.Name(), b.Name()),
		)
	})
}
