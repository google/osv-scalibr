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

// Package podman extracts container inventory from podman database.
package podman

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "containers/podman"
)

// Config is the configuration for the Extractor.
type Config struct{}

// DefaultConfig returns the default configuration for the podman extractor.
func DefaultConfig() Config {
	return Config{}
}

// Extractor extracts containers from the podman db file.
type Extractor struct{}

// New returns a podman container inventory extractor.
func New(cfg Config) *Extractor {
	return &Extractor{}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// Config returns the configuration of the extractor.
func (e Extractor) Config() Config {
	return Config{}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	// todo check this
	return &plugin.Capabilities{
		DirectFS:      true,
		RunningSystem: true,
	}
}

// FileRequired returns true if the specified file matches podman metaDB file pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	panic("unimplemented")
}

// Extract container inventory through the podman db file passed as the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {

	path := filepath.Join(input.Root, input.Path)

	state, err := getDBState(path)
	if err != nil {
		return nil, fmt.Errorf("Error opening file: %s with error: %w", path, err)
	}
	defer state.Close()

	ctrs, err := state.AllContainers()
	if err != nil {
		return nil, fmt.Errorf("Error listing pods in file: %s with error: %w", path, err)
	}

	ivs := make([]*extractor.Inventory, len(ctrs))
	for _, ctr := range ctrs {
		ivs = append(ivs, &extractor.Inventory{
			Name:      ctr.config.RootfsImageName,
			Version:   ctr.config.RootfsImageID,
			Locations: []string{ctr.config.Rootfs},
			Metadata: &Metadata{
				ExposedPorts: ctr.config.ExposedPorts,
			},
		})
	}
	return ivs, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL { return nil }

// Ecosystem returns no ecosystem since the Inventory is not a software package.
func (Extractor) Ecosystem(i *extractor.Inventory) string { return "" }
