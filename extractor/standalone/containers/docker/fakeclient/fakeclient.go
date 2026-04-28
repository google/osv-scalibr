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

// Package fakeclient contains a fake implementation of the docker client for testing purposes.
package fakeclient

import (
	"context"
	"slices"

	"github.com/google/osv-scalibr/extractor/standalone/containers/docker"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// FakeClient is a fake implementation of the Docker client.
type FakeClient struct {
	ctrs []container.Summary
}

// New creates a new fake docker client.
func New(ctrs []container.Summary) docker.Client {
	return &FakeClient{
		ctrs: ctrs,
	}
}

// ContainerList returns a list of containers, optionally filtering out non-running ones.
func (f *FakeClient) ContainerList(ctx context.Context, options client.ContainerListOptions) (client.ContainerListResult, error) {
	ctrs := slices.Clone(f.ctrs)
	if !options.All {
		ctrs = slices.DeleteFunc(ctrs, func(ctr container.Summary) bool { return ctr.State != "running" })
	}
	return client.ContainerListResult{Items: ctrs}, nil
}
