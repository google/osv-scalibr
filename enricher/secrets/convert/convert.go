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

// Package convert provides a utility function for converting Veles plugins
// (Detectors and Validators) to SCALIBR core plugins (FilesystemExtractors and Enrichers)
package convert

import (
	"context"
	"errors"
	"reflect"

	"github.com/google/osv-scalibr/enricher"
	se "github.com/google/osv-scalibr/enricher/secrets"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/veles"
)

// FromVelesValidator converts a Veles Validator into a SCALIBR Enricher plugin.
// This allows enabling Veles Validators individually like regular SCALIBR plugins.
// The wrapped Enricher does not do any enrichment on its own - it's a placeholder plugin
// that is used to configure the Veles validator before the scan starts.
func FromVelesValidator[S veles.Secret](velesValidator veles.Validator[S], name string, version int) func() enricher.Enricher {
	return func() enricher.Enricher {
		return &validatorWrapper{
			velesValidator: veles.NewGenericValidator(velesValidator),
			typ:            reflect.TypeFor[S](),
			name:           name,
			version:        version,
		}
	}
}

// validatorWrapper is a wrapper around the veles.Validator interface that
// implements the additional functions of the filesystem Enricher interface.
type validatorWrapper struct {
	velesValidator veles.GenericValidator
	// The secret type that this validator checks.
	typ     reflect.Type
	name    string
	version int
}

// Validate checks whether the given secret is valid.
func (v *validatorWrapper) Validate(ctx context.Context, s veles.Secret) (veles.ValidationStatus, error) {
	return v.velesValidator.Validate(ctx, s)
}

// Name of the enricher.
func (v *validatorWrapper) Name() string {
	return v.name
}

// Version of the enricher.
func (v *validatorWrapper) Version() int {
	return v.version
}

// Requirements of the enricher.
func (v *validatorWrapper) Requirements() *plugin.Capabilities {
	// Veles plugins don't have any special requirements.
	return &plugin.Capabilities{}
}

// RequiredPlugins returns an empty list - While it works on the results of the
// secret detector plugins, the Enricher itself can run independently.
func (v *validatorWrapper) RequiredPlugins() []string {
	return []string{}
}

// Enrich is a dummy function to satisfy the interface requirements.
// It always returns an error since wrapped secret scanner plugins all run through the
// central veles Enricher plugin.
func (v *validatorWrapper) Enrich(ctx context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	return errors.New("Enrich not implemented - Plugin should run through the central Veles validation engine")
}

// Assert that validatorWrapper implements the required interfaces.
var _ veles.GenericValidator = &validatorWrapper{}
var _ enricher.Enricher = &validatorWrapper{}

// SetupVelesEnrichers configures the central Veles secret validation plugin using the placeholder
// enrichers found in the enricher list. Returns the updated enricher list.
func SetupVelesEnrichers(enrichers []enricher.Enricher) ([]enricher.Enricher, error) {
	result := make([]enricher.Enricher, 0, len(enrichers))
	validators := []veles.ValidationEngineOption{}
	for _, e := range enrichers {
		if v, ok := e.(*validatorWrapper); ok {
			validators = append(validators, veles.WithGenericValidator(v, v.typ))
		} else {
			result = append(result, e)
		}
	}

	// Add the veles enricher with the configured validators.
	if len(validators) != 0 {
		engine := veles.NewValidationEngine(validators...)
		result = append(result, se.NewWithEngine(engine))
	}

	return result, nil
}
