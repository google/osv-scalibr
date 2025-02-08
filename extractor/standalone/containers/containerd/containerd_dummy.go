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

//go:build !linux

package containerd

import (
	"context"
	"fmt"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// Name of the extractor
const Name = "containers/containerd-runtime"

// Config is the configuration for the Extractor.
type Config struct{}

// DefaultConfig returns the default configuration for the containerd extractor.
func DefaultConfig() Config {
	return Config{}
}

// Extractor implements the containerd runtime extractor.
type Extractor struct{}

// New creates a new containerd client and returns a containerd container inventory extractor.
// No op for non-Linux.
func New(cfg Config) *Extractor {
	return &Extractor{}
}

// Config returns the configuration of the extractor.
func (e Extractor) Config() Config {
	return Config{}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// Extract is a no-op for non-Linux.
func (e *Extractor) Extract(ctx context.Context, input *standalone.ScanInput) ([]*extractor.Inventory, error) {
	return nil, fmt.Errorf("only supported on Linux")
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e *Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return nil
}

// Ecosystem returns no ecosystem since the Inventory is not a software package.
func (e Extractor) Ecosystem(i *extractor.Inventory) string { return "" }
