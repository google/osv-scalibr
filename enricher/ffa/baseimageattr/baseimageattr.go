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

// Package baseimageattr enriches packages from unknown binaries extractor with potential base images from deps.dev.
package baseimageattr

import (
	"context"
	"slices"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/baseimage"
	"github.com/google/osv-scalibr/extractor/filesystem/ffa/unknownbinariesextr"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name of the base image attribution enricher.
	Name = "ffa/baseimageattr"
)

// Enricher enriches the inventory by filtering out packages that are accounted for in a base image.
type Enricher struct {
}

// New returns a new Enricher.
func New(_ *cpb.PluginConfig) (enricher.Enricher, error) {
	return &Enricher{}, nil
}

// Name of the base image attribution enricher.
func (*Enricher) Name() string { return Name }

// Version of the base image attribution enricher.
func (*Enricher) Version() int { return 0 }

// Requirements of the base image attribution enricher.
func (*Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{Network: plugin.NetworkOnline}
}

// RequiredPlugins returns a list of Plugins that need to be enabled for this Enricher to work.
func (*Enricher) RequiredPlugins() []string {
	return []string{unknownbinariesextr.Name, baseimage.Name}
}

// Enrich filters packages from unknown binaries extractor that can be attributed to a base image.
func (e *Enricher) Enrich(ctx context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	for _, pkg := range inv.Packages {
		// Packages that are not extracted by unknown binaries extractor should be excluded
		if !slices.Contains(pkg.Plugins, unknownbinariesextr.Name) {
			continue
		}
		// Packages that does not have layer metadata cannot be attributed
		if pkg.LayerMetadata == nil {
			continue
		}

		lmd := pkg.LayerMetadata

		// Package does not have a base image match
		if lmd.BaseImageIndex == 0 {
			continue
		}

		md, ok := pkg.Metadata.(*unknownbinariesextr.UnknownBinaryMetadata)
		// Should not happen as all packges from unknown binaries extractor should have this metadata
		if !ok {
			continue
		}
		md.Attribution.BaseImage = true
	}

	return nil
}
