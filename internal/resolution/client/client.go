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

// Package client provides clients required by dependency resolution.
package client

import (
	"deps.dev/util/resolve"
)

// DependencyClient is the interface of the client required by dependency resolution.
type DependencyClient interface {
	resolve.Client
	// WriteCache writes a manifest-specific resolution cache.
	WriteCache(filepath string) error
	// LoadCache loads a manifest-specific resolution cache.
	LoadCache(filepath string) error
	// AddRegistries adds the specified registries to fetch data.
	AddRegistries(registries []Registry) error
}

// Registry is the interface of a registry to fetch data.
type Registry any
