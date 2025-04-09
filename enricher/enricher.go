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

	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
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
