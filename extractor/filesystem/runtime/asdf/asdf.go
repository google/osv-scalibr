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

// Package asdf extracts the installed language runtime names and versions from asdf .tool-version files.
package asdf

import (
	"bufio"
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	asdfmeta "github.com/google/osv-scalibr/extractor/filesystem/runtime/asdf/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/asdf"
)

// Extractor extracts asdf tools.
type Extractor struct{}

// New returns a new instance of the extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the file name is '.tool-versions'.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return path.Base(api.Path()) == ".tool-versions"
}

func parseToolLine(line string) (tool string, versions []string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil, false
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", nil, false
	}
	return fields[0], fields[1:], true
}

// Extract extracts packages from the asdf .tool-versions file.
//
// Reference: https://asdf-vm.com/manage/configuration.html#tool-versions
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	scanner := bufio.NewScanner(input.Reader)
	var pkgs []*extractor.Package

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		tool, versions, ok := parseToolLine(scanner.Text())
		if !ok {
			continue
		}

		for _, v := range versions {
			// Skip entries that don't store version strings.
			if v == "system" || strings.HasPrefix(v, "file:") {
				continue
			}
			pkgs = append(pkgs, &extractor.Package{
				Name:      tool,
				Version:   v,
				PURLType:  purl.TypeAsdf,
				Locations: []string{input.Path},
				Metadata: &asdfmeta.Metadata{
					ToolName:    tool,
					ToolVersion: v,
				},
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return inventory.Inventory{}, err
	}
	return inventory.Inventory{Packages: pkgs}, nil
}
