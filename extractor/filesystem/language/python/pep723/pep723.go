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

// Package pep723 extracts Python package dependencies from PEP 723 inline script metadata.
package pep723

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/pep723"
	// MaxFileSize is the maximum size of a Python script we will parse (1 MB).
	MaxFileSize = 1024 * 1024
)

var (
	startRegex = regexp.MustCompile(`^# /// script\s*$`)
	endRegex   = regexp.MustCompile(`^# ///\s*$`)
	nameRegex  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*`)
)

type scriptMetadata struct {
	Dependencies []string `toml:"dependencies"`
}

// Extractor extracts Python packages from PEP 723 inline script metadata.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the file is a Python script.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Ext(api.Path()) == ".py"
}

// Extract extracts Python packages from PEP 723 inline script metadata.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input.Info != nil && input.Info.Size() > MaxFileSize {
		return inventory.Inventory{}, fmt.Errorf("%s: file size %d exceeds maximum %d", Name, input.Info.Size(), MaxFileSize)
	}

	packages, err := ParsePEP723(ctx, input.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}

	for _, pkg := range packages {
		pkg.Location = extractor.LocationFromPath(input.Path)
	}

	return inventory.Inventory{Packages: packages}, nil
}

// ParsePEP723 parses a Python file and extracts PEP 723 dependencies.
func ParsePEP723(ctx context.Context, r io.Reader) ([]*extractor.Package, error) {
	scanner := bufio.NewScanner(r)
	var packages []*extractor.Package
	inBlock := false
	block := strings.Builder{}

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%s halted due to context error: %w", Name, err)
		}

		line := scanner.Text()

		if startRegex.MatchString(line) {
			inBlock = true
			block.Reset()
			continue
		}

		if endRegex.MatchString(line) {
			if inBlock {
				pkgs, err := packagesFromMetadata(block.String())
				if err != nil {
					return nil, err
				}
				packages = append(packages, pkgs...)
			}
			inBlock = false
			continue
		}

		if !inBlock {
			continue
		}

		content, ok := strings.CutPrefix(line, "#")
		if !ok {
			continue
		}
		block.WriteString(strings.TrimPrefix(content, " "))
		block.WriteByte('\n')
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return packages, nil
}

func packagesFromMetadata(content string) ([]*extractor.Package, error) {
	var metadata scriptMetadata
	if err := toml.Unmarshal([]byte(content), &metadata); err != nil {
		return nil, fmt.Errorf("%s: failed to parse PEP 723 TOML: %w", Name, err)
	}

	packages := make([]*extractor.Package, 0, len(metadata.Dependencies))
	for _, dep := range metadata.Dependencies {
		name, version := splitRequirement(dep)
		if name == "" {
			continue
		}
		packages = append(packages, &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purl.TypePyPi,
		})
	}
	return packages, nil
}

func splitRequirement(dep string) (string, string) {
	req, _, _ := strings.Cut(strings.TrimSpace(dep), ";")
	req = strings.TrimSpace(req)
	if req == "" {
		return "", ""
	}

	if name, _, ok := strings.Cut(req, " @ "); ok {
		return trimExtras(strings.TrimSpace(name)), ""
	}

	name := nameRegex.FindString(req)
	if name == "" {
		return "", ""
	}
	name = trimExtras(name)
	version := strings.TrimSpace(strings.TrimPrefix(req, name))
	if strings.HasPrefix(version, "[") {
		if end := strings.Index(version, "]"); end >= 0 {
			version = strings.TrimSpace(version[end+1:])
		}
	}
	return name, version
}

func trimExtras(name string) string {
	name, _, _ = strings.Cut(name, "[")
	return strings.TrimSpace(name)
}

var _ filesystem.Extractor = Extractor{}
