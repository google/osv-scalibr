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

// Package fakeclient contains a fake implementation of the docker client for testing purposes.
package fakeclient

import (
	"context"
	"slices"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/google/osv-scalibr/extractor/standalone/containers/docker"
)

type fakeClient struct {
	ctrs []types.Container
}

func New(ctrs []types.Container) docker.Client {
	return &fakeClient{
		ctrs: ctrs,
	}
}

func (f *fakeClient) ContainerList(ctx context.Context, options container.ListOptions) ([]types.Container, error) {
	ctrs := slices.Clone(f.ctrs)
	if !options.All {
		ctrs = slices.DeleteFunc(ctrs, func(ctr types.Container) bool { return ctr.State != "running" })
	}
	return ctrs, nil
}
