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
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "containers/podman"
)

// Config defines the configuration options for the Extractor.
type Config struct {
	// All specifies whether to list all containers, including those that are not currently running.
	All bool
}

// DefaultConfig returns the default configuration for the podman extractor.
func DefaultConfig() Config {
	return Config{}
}

// Extractor extracts containers from the podman db file.
type Extractor struct {
	cfg Config
}

// New returns a podman container inventory extractor.
func New(cfg Config) *Extractor {
	return &Extractor{cfg: cfg}
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
	return &plugin.Capabilities{
		OS:            plugin.OSLinux,
		DirectFS:      true,
		RunningSystem: true,
	}
}

// FileRequired returns true if the specified file matches podman db file pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := filepath.ToSlash(api.Path())

	if strings.HasSuffix(path, "/containers/storage/db.sql") {
		return true
	}

	if strings.HasSuffix(path, "/containers/storage/libpod/bolt_state.db") {
		return true
	}

	return false
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
		return nil, fmt.Errorf("Error listing containers in file: %s with error: %w", path, err)
	}

	ivs := make([]*extractor.Inventory, 0, len(ctrs))
	for _, ctr := range ctrs {
		if !e.cfg.All && ctr.state.Exited {
			continue
		}

		ivs = append(ivs, &extractor.Inventory{
			Name:    ctr.config.RawImageName,
			Version: ctr.config.RootfsImageID,
			Metadata: &Metadata{
				ExposedPorts: ctr.config.ExposedPorts,
				PID:          ctr.state.PID,
				NameSpace:    ctr.config.Namespace,
				StartedTime:  ctr.state.StartedTime,
				FinishedTime: ctr.state.FinishedTime,
				Status:       ctr.state.State.String(),
				ExitCode:     ctr.state.ExitCode,
				Exited:       ctr.state.Exited,
			},
		})
	}
	return ivs, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL { return nil }

// Ecosystem returns no ecosystem since the Inventory is not a software package.
func (Extractor) Ecosystem(i *extractor.Inventory) string { return "" }
