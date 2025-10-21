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

// Package annotator provides the interface for annotation plugins.
package annotator

import (
	"context"

	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Annotator is the interface for an annotation plugin, used to add additional
// information to scan results such as VEX statements. Annotators have access to
// the filesystem but should ideally not query any external APIs. If you need to
// modify the scan results based on the output of network calls you should use
// the Enricher interface instead.
type Annotator interface {
	plugin.Plugin
	// Annotate annotates the scan results with additional information.
	Annotate(ctx context.Context, input *ScanInput, results *inventory.Inventory) error
}

// Config stores the config settings for the annotation run.
type Config struct {
	Annotators []Annotator
	ScanRoot   *scalibrfs.ScanRoot
}

// ScanInput provides information for the annotator about the scan.
type ScanInput struct {
	// The root of the artifact being scanned.
	ScanRoot *scalibrfs.ScanRoot
}

// Run runs the specified annotators on the scan results and returns their statuses.
func Run(ctx context.Context, config *Config, inventory *inventory.Inventory) ([]*plugin.Status, error) {
	var statuses []*plugin.Status
	if len(config.Annotators) == 0 {
		return statuses, nil
	}

	input := &ScanInput{
		ScanRoot: config.ScanRoot,
	}

	for _, a := range config.Annotators {
		err := a.Annotate(ctx, input, inventory)
		statuses = append(statuses, plugin.StatusFromErr(a, false, err))
	}
	return statuses, nil
}
