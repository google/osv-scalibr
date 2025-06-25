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

// Package filter defines an enricher that filters out vulns with VEX signals.
package filter

import (
	"context"
	"slices"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the name of the enricher.
	Name = "vex/filter"
	// Version is the version of the enricher.
	Version = 0
)

// New returns a new enricher.
func New() enricher.Enricher {
	return &Enricher{}
}

// Enricher removes vulnerabilities that have VEX signals associated.
type Enricher struct{}

// Name of the enricher.
func (*Enricher) Name() string { return Name }

// Version of the enricher.
func (*Enricher) Version() int { return Version }

// Requirements of the enricher.
func (*Enricher) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// RequiredPlugins returns a list of Plugins that need to be enabled for this Enricher to work.
func (*Enricher) RequiredPlugins() []string { return nil }

// Enrich removes vulnerabilities that have VEX signals associated.
func (e *Enricher) Enrich(ctx context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	inv.PackageVulns = slices.DeleteFunc(inv.PackageVulns, func(f *inventory.PackageVuln) bool {
		return len(f.ExploitabilitySignals) > 0
	})
	inv.GenericFindings = slices.DeleteFunc(inv.GenericFindings, func(f *inventory.GenericFinding) bool {
		return len(f.ExploitabilitySignals) > 0
	})
	return nil
}
