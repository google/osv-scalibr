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

// Package unknownbinariesextr identifies binary files on the filesystem and adds them as packages.
package unknownbinariesextr

import (
	"context"

	//nolint:gosec //md5 used to identify files, not for security purposes
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique name of this extractor.
	Name = "ffa/unknownbinaries"
)

// Extractor finds unknown binaries on the filesystem
type Extractor struct {
}

// Name of the extractor.
func (e *Extractor) Name() string { return Name }

// Version of the extractor.
func (e *Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e *Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		OS: plugin.OSUnix,
	}
}

// FileRequired returns true for likely directories to contain vendored c/c++ code
func (e *Extractor) FileRequired(fapi filesystem.FileAPI) bool {
	return filesystem.IsInterestingExecutable(fapi)
}

// Extract determines the most likely package version from the directory and returns them as
// package entries with "Location" filled in.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	return inventory.Inventory{
		Packages: []*extractor.Package{
			{
				Locations: []string{input.Path},
			},
		}}, nil
}

var _ filesystem.Extractor = &Extractor{}
