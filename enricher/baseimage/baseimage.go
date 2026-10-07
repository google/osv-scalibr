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

	// Map from chain ID to deduplicated repository names it belongs to.
	chainIDToRepos := make(map[string][]string)
	var enrichErr error
	for _, cim := range inv.ContainerImageMetadata {
		if cim.LayerMetadata == nil {
			continue
		}

		// Placeholder for the scanned image itself.
		if len(cim.BaseImages) == 0 {
			cim.BaseImages = [][]*extractor.BaseImageDetails{{}}
		}

		chainIDsByLayerIndex := make([]digest.Digest, len(cim.LayerMetadata))
		reposByLayerIndex := make([][]string, len(cim.LayerMetadata))
		g, ctx := errgroup.WithContext(ctx)
		g.SetLimit(maxConcurrentRequests)

		// We do not want to use the normal chainID of the layer, because it does not include empty
		// layers. Deps.dev does a special calculation of the chainID that includes empty layers, so we
		// do the same here.
		for i, l := range cim.LayerMetadata {
			diffID := l.DiffID
			if diffID == "" {
				diffID = digestSHA256EmptyTar
			}

			// first populate this with diffIDs
			chainIDsByLayerIndex[i] = diffID
		}
		// This replaces the diffIDs with chainIDs for the corresponding index.
		identity.ChainIDs(chainIDsByLayerIndex)

		for i, chainID := range chainIDsByLayerIndex {
			if repos, ok := chainIDToRepos[chainID.String()]; ok {
				// Already cached, we can just skip this layer.
				reposByLayerIndex[i] = repos
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

				var repos []string
				if resp != nil {
					for _, result := range resp.Results {
						if result != nil && result.Repository != "" && !slices.Contains(repos, result.Repository) {
							repos = append(repos, result.Repository)
						}
					}
				}
				reposByLayerIndex[i] = repos
				return nil
			})
		}

		if err := g.Wait(); err != nil {
			enrichErr = multierr.Append(enrichErr, err)
			// Move onto the next image
			continue
		}

		for i, chainID := range chainIDsByLayerIndex {
			chainIDToRepos[chainID.String()] = reposByLayerIndex[i]
		}

		// Pass 1: Collect base images at their topmost (newest) layer boundary, keeping
		// pre-existing entries from earlier plugins ahead of deps.dev matches.
		byTopLayer := make([][]*extractor.BaseImageDetails, len(cim.LayerMetadata))
		seenExisting := make([]bool, len(cim.BaseImages))
		var lastRepos []string
		for i, lm := range slices.Backward(cim.LayerMetadata) {
			if idx := lm.BaseImageIndex; idx > 0 && idx < len(cim.BaseImages) && !seenExisting[idx] {
				seenExisting[idx] = true
				for _, bid := range cim.BaseImages[idx] {
					bid.ChainID = chainIDsByLayerIndex[i]
					byTopLayer[i] = append(byTopLayer[i], bid)
				}
			}

			if repos := reposByLayerIndex[i]; len(repos) > 0 && !sameRepos(repos, lastRepos) {
				lastRepos = repos
				for _, repo := range repos {
					byTopLayer[i] = append(byTopLayer[i], &extractor.BaseImageDetails{
						Repository: repo,
						Registry:   "docker.io", // Currently all deps.dev images are from the docker mirror.
						ChainID:    chainIDsByLayerIndex[i],
						Plugin:     Name,
					})
				}
			}
		}

		// Pass 2: Pack per-layer boundaries back into cim.BaseImages and propagate BaseImageIndex
		// from newest to oldest layer.
		cim.BaseImages = [][]*extractor.BaseImageDetails{{}}
		for i, lm := range slices.Backward(cim.LayerMetadata) {
			if len(byTopLayer[i]) > 0 {
				cim.BaseImages = append(cim.BaseImages, byTopLayer[i])
			}
			lm.BaseImageIndex = len(cim.BaseImages) - 1
		}
	}

	return enrichErr
}

// sameRepos reports whether two deduplicated repository slices contain the same set of names.
func sameRepos(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, r := range a {
		if !slices.Contains(b, r) {
			return false
		}
	}
	return true
}
