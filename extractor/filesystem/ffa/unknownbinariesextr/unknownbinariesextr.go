// Copyright 2026 Google LLC
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
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/opencontainers/go-digest"
)

const (
	// Name is the unique name of this extractor.
	Name = "ffa/unknownbinariesextr"
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

// New returns a new unknown binaries extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{}, nil
}

// FileRequired returns true for likely directories to contain vendored c/c++ code
func (e *Extractor) FileRequired(fapi filesystem.FileAPI) bool {
	return filesystem.IsInterestingExecutable(fapi)
}

// Extract determines the most likely package version from the directory and returns them as
// package entries with "Location" filled in.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	// Compute file hash
	fileHash, err := digest.SHA256.FromReader(input.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}

	return inventory.Inventory{
		Packages: []*extractor.Package{
			{
				Locations: []string{input.Path},
				Metadata: &UnknownBinaryMetadata{
					FileHash: fileHash,
				},
			},
		}}, nil
}
