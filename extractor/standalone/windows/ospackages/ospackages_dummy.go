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

//go:build !windows

// Package ospackages extracts installed softwares on Windows.
package ospackages

import (
	"context"
	"errors"

	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name of the extractor
const Name = "windows/ospackages"

// Configuration for the extractor.
type Configuration struct{}

// DefaultConfiguration for the extractor. On non-windows, it contains nothing.
func DefaultConfiguration() Configuration {
	return Configuration{}
}

// Extractor implements the ospackages extractor.
type Extractor struct{}

// New creates a new Extractor from a given configuration.
func New(config Configuration) standalone.Extractor {
	return &Extractor{}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() standalone.Extractor {
	return New(DefaultConfiguration())
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{OS: plugin.OSWindows}
}

// Extract is a no-op for Linux.
func (e *Extractor) Extract(ctx context.Context, input *standalone.ScanInput) (inventory.Inventory, error) {
	return inventory.Inventory{}, errors.New("only supported on Windows")
}
