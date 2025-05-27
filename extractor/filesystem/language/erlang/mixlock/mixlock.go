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

// Package mixlock extracts erlang mix.lock files.
package mixlock

import (
	"context"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/erlang/mixlock/mixlockutils"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique name of this extractor.
	Name = "erlang/mixlock"
)

// Extractor extracts erlang mix.lock files.
type Extractor struct{}

// New returns a new instance of this Extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file is a mix.lock file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "mix.lock"
}

// Extract extracts packages from Erlang mix.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	// Parse the Mix.lock file using mixlockutils
	return mixlockutils.ParseMixLockFile(input)
}

var _ filesystem.Extractor = Extractor{}
