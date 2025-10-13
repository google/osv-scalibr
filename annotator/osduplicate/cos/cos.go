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

// Package cos implements an annotator for language packages that have already been found in
// COS OS packages.
package cos

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the Annotator.
	Name = "vex/os-duplicate/cos"
	// The dir in which all OS-installed COS packages are stored.
	cosPkgDir = "mnt/stateful_partition/var_overlay/db/pkg/"
	// The only mutable path inside COS filesystems.
	mutableDir = "mnt/stateful_partition"
)

// Annotator adds annotations to language packages that have already been found in COS OS packages.
type Annotator struct{}

// New returns a new Annotator.
func New() annotator.Annotator { return &Annotator{} }

// Name of the annotator.
func (Annotator) Name() string { return Name }

// Version of the annotator.
func (Annotator) Version() int { return 0 }

// Requirements of the annotator.
func (Annotator) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{OS: plugin.OSLinux}
}

// Annotate adds annotations to language packages that have already been found in COS OS packages.
func (a *Annotator) Annotate(ctx context.Context, input *annotator.ScanInput, results *inventory.Inventory) error {
	for _, pkg := range results.Packages {
		// Return if canceled or exceeding deadline.
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%s halted at %q because of context error: %w", a.Name(), input.ScanRoot.Path, err)
		}

		if len(pkg.Locations) == 0 {
			continue
		}

		loc := pkg.Locations[0]
		// Annotate packages as OS duplicates if:
		// They're in the OS package installation directory
		if strings.HasPrefix(loc, cosPkgDir) ||
			// Or if they're outside of the user-writable path (only OS-installed packages can live there).
			!strings.HasPrefix(loc, mutableDir) {
			pkg.ExploitabilitySignals = append(pkg.ExploitabilitySignals, &vex.PackageExploitabilitySignal{
				Plugin:          Name,
				Justification:   vex.ComponentNotPresent,
				MatchesAllVulns: true,
			})
		}
	}
	return nil
}
