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

package clienttest

import (
	"os"
	"strings"
	"testing"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/schema"
	"github.com/google/osv-scalibr/clients/resolution"
	"gopkg.in/yaml.v3"
)

// ResolutionUniverse defines a mock resolution universe.
type ResolutionUniverse struct {
	System string `yaml:"system"`
	Schema string `yaml:"schema"`
}

type mockDependencyClient struct {
	*resolve.LocalClient
}

func (mdc mockDependencyClient) AddRegistries(_ []resolution.Registry) error { return nil }

// NewMockResolutionClient creates a new mock resolution client from the given universe YAML.
func NewMockResolutionClient(t *testing.T, universeYAML string) resolution.DependencyClient {
	t.Helper()
	f, err := os.Open(universeYAML)
	if err != nil {
		t.Fatalf("failed opening mock universe: %v", err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)

	var universe ResolutionUniverse
	if err := dec.Decode(&universe); err != nil {
		t.Fatalf("failed decoding mock universe: %v", err)
	}

	var sys resolve.System
	switch strings.ToLower(universe.System) {
	case "npm":
		sys = resolve.NPM
	case "maven":
		sys = resolve.Maven
	default:
		t.Fatalf("unknown ecosystem in universe: %s", universe.System)
	}

	// schema needs a strict tab indentation, which is awkward to do within the YAML.
	// Replace double space from yaml with single tab
	universe.Schema = strings.ReplaceAll(universe.Schema, "  ", "\t")
	sch, err := schema.New(universe.Schema, sys)
	if err != nil {
		t.Fatalf("failed parsing schema: %v", err)
	}

	return mockDependencyClient{sch.NewClient()}
}
