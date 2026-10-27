// Copyright 2026 Google LLC
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

// Package buildpacks uses buildpacks.io metadata to annotate images and layers.
package buildpacks

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

// Name is the unique name of this annotator.
const Name = "layerdetails/buildpacks"

// Annotator processes buildpacks.io metadata and attaches it to container images and layers.
type Annotator struct{}

// New returns a new Annotator.
func New(_ *cpb.PluginConfig) (annotator.Annotator, error) { return &Annotator{}, nil }

// Name returns the name of the annotator.
func (*Annotator) Name() string { return Name }

// Version returns the version of the annotator.
func (*Annotator) Version() int { return 0 }

// Requirements returns the requirements of the annotator.
func (*Annotator) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// Annotate executes the annotator.
func (*Annotator) Annotate(ctx context.Context, _ *annotator.ScanInput, inv *inventory.Inventory) error {
	for _, cim := range inv.ContainerImageMetadata {
		raw, ok := cim.Labels[metadataLabel]
		if !ok || raw == "" {
			continue
		}

		meta := &metadata{}
		if err := json.Unmarshal([]byte(raw), meta); err != nil {
			return fmt.Errorf("failed to unmarshal OCI label %s: %w", metadataLabel, err)
		}

		attrsByDiffID := map[string][]string{}
		addAttr := func(sha, tag string) {
			if !slices.Contains(attrsByDiffID[sha], tag) {
				attrsByDiffID[sha] = append(attrsByDiffID[sha], "buildpacks/"+tag)
			}
		}

		for _, app := range meta.App {
			addAttr(app.SHA, "app")
		}
		addAttr(meta.SBOM.SHA, "sbom")
		addAttr(meta.Config.SHA, "config")
		addAttr(meta.Launcher.SHA, "launcher")
		for _, pack := range meta.Buildpacks {
			for name, layer := range pack.Layers {
				addAttr(layer.SHA, fmt.Sprintf("buildpack/%s/%s", pack.Key, name))
			}
		}

		for _, lm := range cim.LayerMetadata {
			if attrs, ok := attrsByDiffID[lm.DiffID.String()]; ok {
				slices.Sort(attrs)
				for _, tag := range attrs {
					lm.Attributes = append(lm.Attributes, &extractor.LayerAttribute{
						Plugin: Name,
						Value:  tag,
					})
				}
			}
		}
	}
	return nil
}

// In sync with the upstream Buildpacks lifecycle metadata spec. See:
// https://github.com/buildpacks/spec/blob/main/platform.md#iobuildpackslifecyclemetadata-json

const metadataLabel = "io.buildpacks.lifecycle.metadata"

type metadata struct {
	App        []layer `json:"app"`
	SBOM       layer   `json:"sbom"`
	Config     layer   `json:"config"`
	Launcher   layer   `json:"launcher"`
	Buildpacks []pack  `json:"buildpacks"`
}

type layer struct {
	SHA string `json:"sha"`
}

type pack struct {
	Key     string           `json:"key"`
	Version string           `json:"version"`
	Layers  map[string]layer `json:"layers"`
}
