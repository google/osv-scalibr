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
	"context"
	"errors"
	"fmt"
	"path/filepath"

	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

var (
	// ErrNoDirectFS is returned when an enricher requires direct filesystem access but the scan root is nil.
	ErrNoDirectFS = errors.New("enrichment requires direct filesystem access but scan root is nil")
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
	// FS for file access. This is rooted at Root.
	FS scalibrfs.FS
	// The root directory of the artifact being scanned.
	Root string
}

// Run runs the specified enrichers and returns their statuses.
func Run(ctx context.Context, config *Config, inventory *inventory.Inventory) ([]*plugin.Status, error) {
	var statuses []*plugin.Status
	if len(config.Enrichers) == 0 {
		return statuses, nil
	}

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
			FS:   config.ScanRoot.FS,
			Root: config.ScanRoot.Path,
		}
	}

	for _, e := range config.Enrichers {
		err := e.Enrich(ctx, input, inventory)
		// TODO - b/410630503: Support partial success.
		statuses = append(statuses, plugin.StatusFromErr(e, false, err))
	}
	return statuses, nil
}
