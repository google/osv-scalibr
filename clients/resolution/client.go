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

// Package resolution provides clients required by dependency resolution.
package resolution

import (
	"context"

	"deps.dev/util/resolve"
)

// ClientWithRegistries is a resolve.Client that allows package registries to be added.
type ClientWithRegistries interface {
	resolve.Client
	// AddRegistries adds the specified registries to fetch data.
	AddRegistries(ctx context.Context, registries []Registry) error
}

// Registry is the interface of a registry to fetch data.
type Registry any
