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

// Package opam extracts OCaml packages from opam install files.
package opam

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name          = "ocaml/opam"
	installSuffix = ".opam-switch/install"
)

// Extractor extracts OCaml packages from opam install files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the file path matches opam install files.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	normalized := filepath.ToSlash(api.Path())
	return strings.HasSuffix(normalized, installSuffix)
}

// Extract extracts packages from the opam install file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	packages, err := ParseInstall(ctx, input.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}

	for _, pkg := range packages {
		pkg.Locations = []string{input.Path}
	}

	return inventory.Inventory{Packages: packages}, nil
}

// ParseInstall parses an opam install file or opam list output.
func ParseInstall(ctx context.Context, r io.Reader) ([]*extractor.Package, error) {
	packages := make([]*extractor.Package, 0)
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%s halted due to context error: %w", Name, err)
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		name, version, ok := splitEntry(fields[0])
		if !ok {
			return nil, fmt.Errorf("invalid opam package entry %q", fields[0])
		}

		packages = append(packages, &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purl.TypeOpam,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return packages, nil
}

func splitEntry(entry string) (string, string, bool) {
	name, version, ok := strings.Cut(entry, ".")
	if !ok || name == "" || version == "" {
		return "", "", false
	}

	return name, version, true
}

var _ filesystem.Extractor = Extractor{}
