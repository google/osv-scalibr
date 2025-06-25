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

// Package containerd extracts container inventory from containerd metadb database.
package containerd

import (
	"context"
	"errors"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name is the name for the extractor
const Name = "containers/containerd"

// Extractor struct.
type Extractor struct{}

// Config struct
type Config struct {
	// MaxMetaDBFileSize is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	MaxMetaDBFileSize int64
}

// DefaultConfig returns the default configuration values.
func DefaultConfig() Config { return Config{} }

// New returns an extractor.
func New(cfg Config) *Extractor {
	return &Extractor{}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired always returns false.
func (e Extractor) FileRequired(_ filesystem.FileAPI) bool {
	return false
}

// Extract not implemented.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	return inventory.Inventory{}, errors.New("not supported")
}
