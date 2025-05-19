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

// Package fakeenricher provides an Enricher implementation to be used in tests.
package fakeenricher

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/mitchellh/hashstructure/v2"
)

// Enricher is a fake enricher implementation to be used in tests.
type Enricher struct {
	name            string
	version         int
	capabilities    *plugin.Capabilities
	requiredPlugins []string
	wantEnrich      map[uint64]InventoryAndErr
}

// Config for creating a fake enricher.
type Config struct {
	Name            string
	Version         int
	Capabilities    *plugin.Capabilities
	RequiredPlugins []string
	WantEnrich      map[uint64]InventoryAndErr
}

// InventoryAndErr is the expected enrichment response for a given input and inventory.
type InventoryAndErr struct {
	Inventory *inventory.Inventory
	Err       error
}

type inputAndInventory struct {
	Input     *enricher.ScanInput
	Inventory *inventory.Inventory
}

// New creates a new fake enricher.
//
// The expected usage in tests is to create a fake enricher with the expected input and inventory
// to enrichment response mapping.
// Example:
//
//	key, err := fakeenricher.Hash(tc.scanInput, tc.inventory)
//	if err != nil {
//		t.Fatalf("failed to hash input and inventory: %v", err)
//	}
//	wantEnrich := map[uint64]fakeenricher.InventoryAndErr{
//		key: fakeenricher.InventoryAndErr{
//			Inventory: tc.wantInventory,
//			Err:       tc.wantErr,
//		},
//	}
//	e := fakeenricher.New(&fakeenricher.Config{
//		Name:            "FakeEnricher",
//		Version:         1,
//		Capabilities:    &plugin.Capabilities{},
//		RequiredPlugins: []string{},
//		WantEnrich:      wantEnrich,
//	})
//	err := e.Enrich(ctx, tc.scanInput, tc.inventory)
//	if !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
//		t.Fatalf("e.Enrich(%+v, %+v, %+v) error: got %v, want %v\n", ctx, tc.scanInput, tc.inventory, err, tc.wantErr)
//	}
//	if diff := cmp.Diff(tc.wantInventory, tc.inventory); diff != "" {
//		t.Fatalf("e.Enrich(%+v, %+v, %+v) returned unexpected diff (-want +got):\n%s", ctx, tc.scanInput, tc.inventory, diff)
//	}
//
// For convenience, the MustNew and MustHash functions can be used to create a fake enricher and set
// behavior which will fail the test if an error is returned.
func New(cfg *Config) (*Enricher, error) {
	return &Enricher{
		name:            cfg.Name,
		version:         cfg.Version,
		capabilities:    cfg.Capabilities,
		requiredPlugins: cfg.RequiredPlugins,
		wantEnrich:      cfg.WantEnrich,
	}, nil
}

// MustNew creates a new fake enricher and fails the test if an error is returned.
func MustNew(t *testing.T, cfg *Config) *Enricher {
	t.Helper()
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create fake enricher: %v", err)
	}
	return e
}

// Name returns the enricher's name.
func (e *Enricher) Name() string { return e.name }

// Version returns the enricher's version.
func (e *Enricher) Version() int { return e.version }

// Requirements about the scanning environment, e.g. "needs to have network access".
func (e *Enricher) Requirements() *plugin.Capabilities { return e.capabilities }

// RequiredPlugins returns a list of Plugins that need to be enabled for this Enricher to run.
func (e *Enricher) RequiredPlugins() []string { return e.requiredPlugins }

// Enrich enriches the scan results with additional information.
func (e *Enricher) Enrich(ctx context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	key, err := Hash(input, inv)
	if err != nil {
		return err
	}
	invAndErr, ok := e.wantEnrich[key]
	if !ok {
		return fmt.Errorf("no enrichment response for key %d, input: %v, inventory: %v", key, input, inv)
	}
	newInv := invAndErr.Inventory
	inv.Packages = newInv.Packages
	inv.Findings = newInv.Findings
	return invAndErr.Err
}

// Hash returns a hash of the input and inventory. This is used to match the input and inventory
// to the expected enrichment response.
func Hash(input *enricher.ScanInput, inventory *inventory.Inventory) (uint64, error) {
	ii := &inputAndInventory{
		Input:     input,
		Inventory: inventory,
	}
	return hashstructure.Hash(ii, hashstructure.FormatV2, nil)
}

// MustHash returns a hash of the input and inventory. This is used to match the input and inventory
// to the expected enrichment response.
func MustHash(t *testing.T, input *enricher.ScanInput, inventory *inventory.Inventory) uint64 {
	t.Helper()
	hash, err := Hash(input, inventory)
	if err != nil {
		t.Fatalf("failed to hash input and inventory: %v", err)
	}
	return hash
}
