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

//go:build linux

package podman

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
)

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
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	path := filepath.Join(input.Root, input.Path)

	state, err := getDBState(path)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("error opening file: %s with error: %w", path, err)
	}
	defer state.Close()

	ctrs, err := state.AllContainers()
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("error listing containers in file: %s with error: %w", path, err)
	}

	pkgs := make([]*extractor.Package, 0, len(ctrs))
	for _, ctr := range ctrs {
		if !e.cfg.IncludeStopped && ctr.state.Exited {
			continue
		}

		pkgs = append(pkgs, &extractor.Package{
			Name:      ctr.config.RawImageName,
			Version:   ctr.config.RootfsImageID,
			Locations: []string{input.Path},
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
	return inventory.Inventory{Packages: pkgs}, nil
}
