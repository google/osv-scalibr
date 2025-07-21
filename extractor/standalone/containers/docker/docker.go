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

// Package docker extracts container inventory from docker API.
package docker

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique name of this extractor.
	Name = "containers/docker"
)

// Extractor implements the docker extractor.
type Extractor struct {
	client Client
}

// New returns an extractor
func New() standalone.Extractor {
	return &Extractor{}
}

// NewWithClient returns an extractor which uses a specified docker client.
func NewWithClient(c Client) standalone.Extractor {
	return &Extractor{client: c}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{RunningSystem: true}
}

// Extract extracts containers from the docker API.
func (e *Extractor) Extract(ctx context.Context, input *standalone.ScanInput) (inventory.Inventory, error) {
	if e.client == nil {
		var err error
		e.client, err = client.NewClientWithOpts(client.WithAPIVersionNegotiation())
		if err != nil {
			return inventory.Inventory{}, fmt.Errorf("cannot connect with docker %w", err)
		}
	}

	// extract running containers
	containers, err := e.client.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("error fetching containers: %w", err)
	}

	pkgs := make([]*extractor.Package, 0, len(containers))
	for _, ctr := range containers {
		pkgs = append(pkgs, &extractor.Package{
			Name:    ctr.Image,
			Version: ctr.ImageID,
			Metadata: &Metadata{
				ImageName:   ctr.Image,
				ImageDigest: ctr.ImageID,
				ID:          ctr.ID,
				Ports:       ctr.Ports,
			},
		})
	}
	return inventory.Inventory{Packages: pkgs}, nil
}
