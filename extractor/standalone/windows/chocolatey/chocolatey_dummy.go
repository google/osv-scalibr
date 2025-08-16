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

// Package chocolatey provides a dummy implementation for non-Windows platforms.
package chocolatey

import (
	"context"
	"errors"

	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique name of this extractor.
	Name = "windows/chocolatey"
)

// Config is the configuration for the Extractor.
type Config struct {
	ChocolateyPath string
}

// DefaultConfig returns the default configuration for the extractor.
func DefaultConfig() Config {
	return Config{}
}

// Extractor is a dummy implementation for non-Windows platforms.
type Extractor struct{}

// New returns a dummy Chocolatey extractor for non-Windows platforms.
func New(cfg Config) *Extractor {
	return &Extractor{}
}

// NewDefault returns a dummy extractor.
func NewDefault() standalone.Extractor { return New(DefaultConfig()) }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 1 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		OS:            plugin.OSWindows,
		DirectFS:      true,
		RunningSystem: true,
	}
}

// Extract returns an error on non-Windows platforms.
func (e Extractor) Extract(ctx context.Context, input *standalone.ScanInput) (inventory.Inventory, error) {
	return inventory.Inventory{}, errors.New("Chocolatey extractor is only supported on Windows")
}