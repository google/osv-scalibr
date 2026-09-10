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

// Package sdp extracts files that may contain sensitive data.
package sdp

import (
	"context"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name is the name for the sdp extractor.
const Name = "sdp/candidatefiles"

// Extractor extracts files that may contain sensitive data.
type Extractor struct{}

// New returns a sdp extractor.
func New() filesystem.Extractor {
	return &Extractor{}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the file's extension is in the extToType map.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	if api.Path() == "" {
		return false
	}
	// Include files with no extension.
	if getExtension(api.Path()) == "" {
		return true
	}
	return getFileTypeForPath(api.Path()) != inventory.UnknownFileType
}

// Extract extracts the file and adds it to the inventory.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	sd := &inventory.SensitiveData{
		Name:     input.Path,
		Location: input.Path,
		FileType: getFileTypeForPath(input.Path),
	}
	return inventory.Inventory{SensitiveData: []*inventory.SensitiveData{sd}}, nil
}
