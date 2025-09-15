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

	"github.com/google/osv-scalibr/clients/depsdev/v1alpha1/grpcclient"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"go.uber.org/multierr"
)

const (
	// Name is the name of the base image enricher.
	Name = "baseimage"
	// Version is the version of the base image enricher.
	Version = 0
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

		for _, lm := range cim.LayerMetadata {
			chainID := lm.ChainID.String()
			// Only enrich layers that have a chain ID.
			if chainID == "" {
				continue
			}

			baseImages, ok := chainIDToBaseImage[chainID]
			if !ok {
				// Query deps.dev for the container image repository.
				req := &Request{
					ChainID: chainID,
				}
				resp, err := e.client.QueryContainerImages(ctx, req)
				if err != nil {
					enrichErr = multierr.Append(enrichErr, fmt.Errorf("failed to query container images for chain ID %q: %w", chainID, err))
					continue
				}
				// If the layer exists in any base image, mark the package as in a base image.
				if resp != nil && resp.Results != nil && len(resp.Results) > 0 {
					for _, result := range resp.Results {
						if result.Repository != "" {
							baseImages = append(baseImages, &extractor.BaseImageDetails{
								Repository: result.Repository,
								Registry:   "docker.io", // Currently all deps.dev images are from the docker mirror.
								ChainID:    lm.ChainID,
								Plugin:     Name,
							})
						}
					}
				}
				chainIDToBaseImage[chainID] = baseImages
			}

			if len(baseImages) > 0 {
				cim.BaseImages = append(cim.BaseImages, baseImages)
				lm.BaseImageIndex = len(cim.BaseImages) - 1
			}
		}
	}

	return enrichErr
}
