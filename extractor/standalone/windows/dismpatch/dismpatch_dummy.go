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

// Package dismpatch extract patch level from the DISM command line tool.
package dismpatch

import (
	"context"
	"errors"

	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name of the extractor
const Name = "windows/dismpatch"

// Extractor implements the dismpatch extractor.
type Extractor struct{}

// New returns a new instance of the extractor.
func New() standalone.Extractor {
	return &Extractor{}
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
