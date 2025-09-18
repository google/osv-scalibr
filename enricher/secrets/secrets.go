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

// Package secrets contains an Enricher that uses Veles Validators to validate
// Secrets found by the Veles Extractor.
package secrets

import (
	"context"
	"time"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/veles"
)

const (
	// Name is the unique name of this Enricher.
	Name = "secrets/velesvalidate"

	version = 1
)

var _ enricher.Enricher = &Enricher{}

// Enricher uses a Veles ValidationEngine to validate Secrets found by Veles.
type Enricher struct {
	engine *veles.ValidationEngine
}

// AddValidator adds a Validator for a specific type of Secret to the underlying validation engine.
//
// Returns whether there was already a Validator in place that now got replaced.
func AddValidator[S veles.Secret](e *Enricher, v veles.Validator[S]) bool {
	return veles.AddValidator(e.engine, v)
}

// NewWithEngine creates a new Enricher with a specified Veles ValidationEngine.
func NewWithEngine(engine *veles.ValidationEngine) enricher.Enricher {
	return &Enricher{engine: engine}
}

// Name of the Enricher.
func (Enricher) Name() string {
	return Name
}

// Version of the Enricher.
func (Enricher) Version() int {
	return version
}

// Requirements of the Enricher.
// Needs network access so it can validate Secrets.
func (Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		Network: plugin.NetworkOnline,
	}
}

// RequiredPlugins returns the plugins that are required to be enabled for this
// Enricher to run. While it works on the results of the filesystem/secrets
// Extractor, the Enricher itself can run independently.
func (Enricher) RequiredPlugins() []string {
	return []string{}
}

// Enrich validates all the Secrets from the Inventory using a Veles
// ValidationEngine.
//
// Each individual Secret maintains its own error in case the validation failed.
func (e *Enricher) Enrich(ctx context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	for _, s := range inv.Secrets {
		if err := ctx.Err(); err != nil {
			return err
		}
		status, err := e.engine.Validate(ctx, s.Secret)
		s.Validation = inventory.SecretValidationResult{
			At:     time.Now(),
			Status: status,
			Err:    err,
		}
	}
	return nil
}
