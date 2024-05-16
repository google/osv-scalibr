// Copyright 2024 Google LLC
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

// Package standalone provides a way to extract in a standalone mode (e.g. a command).
package standalone

import (
	"context"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// Extractor is an interface for plugins that extract information independently. For
// example, a plugin that executes a command or retrieves information from only one file.
type Extractor interface {
	plugin.Plugin

	// Extract the information.
	Extract(ctx context.Context, input *ScanInput) ([]*filesystem.Inventory, error)
	// ToPURL converts an inventory created by this extractor into a PURL.
	ToPURL(i *filesystem.Inventory) (*purl.PackageURL, error)
	// ToCPEs converts an inventory created by this extractor into CPEs, if supported.
	ToCPEs(i *filesystem.Inventory) ([]string, error)
}

// Config for running standalone extractors.
type Config struct {
	Extractors []Extractor
	ScanRoot   string
}

// ScanInput provides information for the extractor about the scan.
type ScanInput struct {
	ScanRoot string
}

// Run the extractors that are specified in the config.
func Run(ctx context.Context, config *Config) ([]*filesystem.Inventory, []*plugin.Status, error) {
	var inventories []*filesystem.Inventory
	var statuses []*plugin.Status

	scanRoot, err := filepath.Abs(config.ScanRoot)
	if err != nil {
		return nil, nil, err
	}

	scanInput := &ScanInput{
		ScanRoot: scanRoot,
	}

	for _, extractor := range config.Extractors {
		inv, err := extractor.Extract(ctx, scanInput)
		if err != nil {
			statuses = append(statuses, plugin.StatusFromErr(extractor, false, err))
			continue
		}
		for _, i := range inv {
			i.Extractor = extractor.Name()
		}

		inventories = append(inventories, inv...)
		statuses = append(statuses, plugin.StatusFromErr(extractor, false, nil))
	}

	return inventories, statuses, nil
}
