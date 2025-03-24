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
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "containers/docker"
)

// Extractor implements the docker extractor.
type Extractor struct {
	client Client
}

// NewDefault returns an extractor
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

// Extractor extracts containers from the docker API.
func (e *Extractor) Extract(ctx context.Context, input *standalone.ScanInput) ([]*extractor.Inventory, error) {
	if e.client == nil {
		var err error
		e.client, err = client.NewClientWithOpts(client.WithAPIVersionNegotiation())
		if err != nil {
			return nil, fmt.Errorf("cannot connect with docker %w", err)
		}
	}

	// extract running containers
	containers, err := e.client.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("Error fetching containers: %w", err)
	}

	// todo filter running containers
	ivs := make([]*extractor.Inventory, 0, len(containers))
	for _, ctr := range containers {
		ivs = append(ivs, &extractor.Inventory{
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
	return ivs, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return nil
}

// Ecosystem returns no ecosystem since the Inventory is not a software package.
func (e Extractor) Ecosystem(i *extractor.Inventory) string { return "" }
