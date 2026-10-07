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

// Package baseimage enriches inventory layer details with potential base images from deps.dev.
package baseimage

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	"go.uber.org/multierr"
	"golang.org/x/sync/errgroup"

	grpcpb "deps.dev/api/v3alpha"
	"github.com/google/osv-scalibr/depsdev"
	"github.com/google/osv-scalibr/plugin/config"
)

const (
	// Name is the name of the base image enricher.
	Name = "baseimage"
	// Version is the version of the base image enricher.
	Version = 0
	// digestSHA256EmptyTar is the canonical sha256 digest of empty tar file -
	// (1024 NULL bytes)
	digestSHA256EmptyTar = digest.Digest("sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef")

	maxConcurrentRequests = 1000
)

// Enricher enriches inventory layer details with potential base images from deps.dev.
type Enricher struct {
	Client Client
}

// New returns a new base image enricher.
func New(cfg *config.PluginConfig) (enricher.Enricher, error) {
	if cfg == nil || cfg.ClientFactories == nil {
		return nil, fmt.Errorf("client factories not configured for %s", Name)
	}
	conn, err := cfg.ClientFactories.GRPCClientConn(depsdev.DepsdevAPI)
	if err != nil {
		return nil, fmt.Errorf("failed to establish gRPC connection for %s: %w", Name, err)
	}
	client := grpcpb.NewInsightsClient(conn)
	return &Enricher{Client: NewClientGRPC(client)}, nil
}

// Name of the base image enricher.
func (*Enricher) Name() string { return Name }

// Version of the base image enricher.
func (*Enricher) Version() int { return Version }

// Requirements of the base image enricher.
func (*Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{Network: plugin.NetworkOnline}
}

// RequiredPlugins returns a list of Plugins that need to be enabled for this Enricher to work.
func (*Enricher) RequiredPlugins() []string {
	return []string{}
}

// Enrich enriches the inventory with base image information from deps.dev.
func (e *Enricher) Enrich(ctx context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	if inv.ContainerImageMetadata == nil {
		return nil
	}

	// Map from chain ID to list of repositories it belongs to.
	chainIDToBaseImage := make(map[string][]*extractor.BaseImageDetails)
	var enrichErr error
	for _, cim := range inv.ContainerImageMetadata {
		if cim.LayerMetadata == nil {
			continue
		}

		// Placeholder for the scanned image itself.
		if len(cim.BaseImages) == 0 {
			cim.BaseImages = [][]*extractor.BaseImageDetails{
				{},
			}
		}

		chainIDsByLayerIndex := make([]digest.Digest, len(cim.LayerMetadata))
		baseImagesByLayerIndex := make([][]*extractor.BaseImageDetails, len(cim.LayerMetadata))
		g, ctx := errgroup.WithContext(ctx)
		g.SetLimit(maxConcurrentRequests)

		// We do not want to use the normal chainID of the layer, because it does not include empty
		// layers. Deps.dev does a special calculation of the chainID that includes empty layers, so we
		// do the same here.
		for i, l := range cim.LayerMetadata {
			diffID := l.DiffID
			if l.DiffID == "" {
				diffID = digestSHA256EmptyTar
			}

			// first populate this with diffIDs
			chainIDsByLayerIndex[i] = diffID
		}
		// This replaces the diffIDs with chainIDs for the corresponding index.
		identity.ChainIDs(chainIDsByLayerIndex)

		for i, chainID := range chainIDsByLayerIndex {
			if val, ok := chainIDToBaseImage[chainID.String()]; ok {
				// Already cached, we can just skip this layer.
				baseImagesByLayerIndex[i] = val
				continue
			}

			// Otherwise query deps.dev for the base images of this layer.
			g.Go(func() error {
				if ctx.Err() != nil {
					// this return value doesn't matter to errgroup.Wait(), since it already errored
					return ctx.Err()
				}

				req := &Request{
					ChainID: chainID.String(),
				}
				resp, err := e.Client.QueryContainerImages(ctx, req)
				if err != nil {
					if !errors.Is(err, errNotFound) {
						// If one query fails even with grpc retries, we cancel the rest of the
						// queries and return the error.
						return fmt.Errorf("failed to query container images for chain ID %q: %w", chainID.String(), err)
					}
					return nil
				}
				var baseImages []*extractor.BaseImageDetails

				if resp != nil && resp.Results != nil && len(resp.Results) > 0 {
					for _, result := range resp.Results {
						if result.Repository != "" {
							baseImages = append(baseImages, &extractor.BaseImageDetails{
								Repository: result.Repository,
								Registry:   "docker.io", // Currently all deps.dev images are from the docker mirror.
								ChainID:    chainID,
								Plugin:     Name,
							})
						}
					}
				}

				// Save to layer map.
				baseImagesByLayerIndex[i] = baseImages

				return nil
			})
		}

		if err := g.Wait(); err != nil {
			enrichErr = multierr.Append(enrichErr, err)
			// Move onto the next image
			continue
		}

		// Cache deps.dev results before merging with existing base images from other plugins.
		for i, chainID := range chainIDsByLayerIndex {
			chainIDToBaseImage[chainID.String()] = baseImagesByLayerIndex[i]
		}

		// Pass 1: Build the base image stack from deps.dev results, walking from the newest
		// layer to the oldest layer. This is because base images are identified by the chain ID
		// of the newest layer in the image, so all older layers must belong to that base image
		// until an older base image is encountered.
		depsDevBaseImages := [][]*extractor.BaseImageDetails{{}}
		depsDevBaseImageIndices := make([]int, len(cim.LayerMetadata))
		for i := range slices.Backward(cim.LayerMetadata) {
			baseImages := baseImagesByLayerIndex[i]
			depsDevBaseImageIndices[i] = len(depsDevBaseImages) - 1

			if len(baseImages) == 0 {
				continue
			}

			// Only append if the current set of baseImages differs from the previous set.
			lastBaseImages := depsDevBaseImages[len(depsDevBaseImages)-1]
			if !slices.EqualFunc(baseImages, lastBaseImages, sameBaseImage) {
				depsDevBaseImages = append(depsDevBaseImages, baseImages)
				// And if we do update, also change the base image index to new last index.
				depsDevBaseImageIndices[i]++
			}
		}

		// Pass 2: Merge the pre-existing base image stack (from earlier plugins) with the
		// deps.dev base image stack. In both stacks, a base image is introduced at the topmost
		// (newest) layer where its index (> 0) first appears when walking backwards.
		// Note that cim.BaseImages (BaseImageChains in proto) is an ordered hierarchy from
		// largest to smallest base image (e.g. [empty, nginx, alpine]) where each entry is
		// keyed by the ChainID of its topmost layer; if one stack identifies a smaller inner
		// base image on an older layer within the other stack's run, that older layer points
		// to the smaller inner base image entry while the larger outer base image remains at
		// its own topmost layer.
		existingBaseImages := cim.BaseImages
		// Placeholder for the scanned image itself.
		cim.BaseImages = [][]*extractor.BaseImageDetails{
			{},
		}
		prevExistingIdx := 0
		prevDepsDevIdx := 0
		for i, lm := range slices.Backward(cim.LayerMetadata) {
			existingIdx := lm.BaseImageIndex
			depsDevIdx := depsDevBaseImageIndices[i]

			var merged []*extractor.BaseImageDetails
			if existingIdx > 0 && existingIdx < len(existingBaseImages) && existingIdx != prevExistingIdx {
				merged = append(merged, existingBaseImages[existingIdx]...)
			}
			if depsDevIdx > 0 && depsDevIdx < len(depsDevBaseImages) && depsDevIdx != prevDepsDevIdx {
				merged = append(merged, depsDevBaseImages[depsDevIdx]...)
			}
			prevExistingIdx = existingIdx
			prevDepsDevIdx = depsDevIdx

			if len(merged) > 0 {
				cim.BaseImages = append(cim.BaseImages, merged)
			}
			lm.BaseImageIndex = len(cim.BaseImages) - 1
		}
	}

	return enrichErr
}

func sameBaseImage(a, b *extractor.BaseImageDetails) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Repository == b.Repository && a.Registry == b.Registry
}
