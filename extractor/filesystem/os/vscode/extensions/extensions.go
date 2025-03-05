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

// Package extensions extracts vscode extensions.
package extensions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// Name is the name for the vscode extensions extractor
const Name = "vscode/extensions"

var extensionsPattern = regexp.MustCompile(`(?m)\.vscode\/extensions\/extensions\.json`)

type extension struct {
	Identifier struct {
		ID string `json:"id"`
	} `json:"identifier"`
	Version  string `json:"version"`
	Location struct {
		Path string `json:"path"`
	} `json:"location"`
	Metadata Metadata `json:"metadata"`
}

func (e *extension) validate() error {
	if e.Identifier.ID == "" {
		return errors.New("extension 'Identifier.ID' cannot be empty")
	}
	if e.Version == "" {
		return errors.New("extension 'Version' cannot be empty")
	}
	return nil
}

// Extractor extracts vscode extensions
type Extractor struct{}

// New returns an vscode extractor.
func New() filesystem.Extractor {
	return &Extractor{}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the file contains vscode extensions information
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	path = filepath.ToSlash(path)
	return extensionsPattern.MatchString(path)
}

// Extract extracts vscode extensions
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var exts []*extension
	if err := json.NewDecoder(input.Reader).Decode(&exts); err != nil {
		return nil, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	ivs := make([]*extractor.Inventory, 0, len(exts))
	for _, ext := range exts {
		if err := ext.validate(); err != nil {
			return nil, fmt.Errorf("bad format in %s: %w", input.Path, err)
		}
		ivs = append(ivs, &extractor.Inventory{
			Name:      ext.Identifier.ID,
			Version:   ext.Version,
			Locations: []string{ext.Location.Path, input.Path},
			Metadata:  ext.Metadata,
		})
	}

	return ivs, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL { return nil }

// Ecosystem is not defined.
func (Extractor) Ecosystem(i *extractor.Inventory) string { return "" }
