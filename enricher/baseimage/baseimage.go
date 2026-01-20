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

// Package baseimage enriches inventory layer details with potential base images from deps.dev.
package baseimage

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"

	"github.com/google/osv-scalibr/clients/depsdev/v1alpha1/grpcclient"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	"go.uber.org/multierr"
	"golang.org/x/sync/errgroup"
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

// Config is the configuration for the base image enricher.
type Config struct {
	Client Client
}

// DefaultConfig returns the default configuration for the base image enricher.
func DefaultConfig() *Config {
	grpcConfig := grpcclient.DefaultConfig()
	grpcclient, err := grpcclient.New(grpcConfig)
	if err != nil {
		log.Fatalf("Failed to create base image client: %v", err)
	}

	client := NewClientGRPC(grpcclient)

	return &Config{
		Client: client,
	}
}

// Enricher enriches inventory layer details with potential base images from deps.dev.
type Enricher struct {
	client Client
}

// New returns a new base image enricher.
func New(cfg *Config) (*Enricher, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}
	if cfg.Client == nil {
		return nil, errors.New("client is nil")
	}
	return &Enricher{client: cfg.Client}, nil
}

// NewDefault returns a new base image enricher with the default configuration.
// It will log.Fatal if the enricher cannot be created.
func NewDefault() enricher.Enricher {
	e, err := New(DefaultConfig())
	if err != nil {
		log.Fatalf("Failed to create base image enricher: %v", err)
	}
	return e
}

// Config returns the configuration for the base image enricher.
func (e *Enricher) Config() *Config {
	return &Config{
		Client: e.client,
	}
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
		cim.BaseImages = [][]*extractor.BaseImageDetails{
			[]*extractor.BaseImageDetails{},
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
				resp, err := e.client.QueryContainerImages(ctx, req)
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

				// Cache and also save to layer map.
				baseImagesByLayerIndex[i] = baseImages

				return nil
			})
		}

		if err := g.Wait(); err != nil {
			enrichErr = multierr.Append(enrichErr, err)
			// Move onto the next image
			continue
		}

		// Loop backwards through the layers, from the newest to the oldest layer.
		// This is because base images are identified by the chain ID of the newest layer in the image,
		// so all older layer must belong to that base image.
		for i, lm := range slices.Backward(cim.LayerMetadata) {
			baseImages := baseImagesByLayerIndex[i]
			lm.BaseImageIndex = len(cim.BaseImages) - 1
			chainIDToBaseImage[chainIDsByLayerIndex[i].String()] = baseImages

			if len(baseImages) == 0 {
				continue
			}

			// Is the current set of baseImages the same as the previous?
			isSame := false
			lastBaseImages := cim.BaseImages[len(cim.BaseImages)-1]
			if len(baseImages) == len(lastBaseImages) {
				isSame = true
				for j := range baseImages {
					if baseImages[j].Repository != lastBaseImages[j].Repository ||
						baseImages[j].Registry != lastBaseImages[j].Registry {
						isSame = false
						break
					}
				}
			}

			if !isSame {
				// Only if it's not the same base image, update
				cim.BaseImages = append(cim.BaseImages, baseImages)
				// And if we do update, also change the base image index to new last index.
				lm.BaseImageIndex++
			}
		}
	}

	return enrichErr
}
