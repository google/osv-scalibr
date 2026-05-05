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

// Package ipythoninstall extracts Python packages from IPython inline install commands.
package ipythoninstall

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/ipythoninstall"

	defaultMaxFileSizeBytes = 10 * units.MiB
)

var (
	ipythonExts = map[string]bool{
		".ipynb": true,
		".ipy":   true,
		".ipyw":  true,
	}

	installCmdRe  = regexp.MustCompile(`^(?:!|%)(pip|conda|uv)\b`)
	packageSpecRe = regexp.MustCompile(`^([A-Za-z0-9._-]+)(==|===|~=|>=|<=|>|<|=)?([A-Za-z0-9*._+-]+)?$`)
)

// Extractor extracts packages from IPython inline install commands.
type Extractor struct {
	maxFileSizeBytes int64
}

// New returns an IPython inline install extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}
	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is an IPython notebook/source file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	ext := strings.ToLower(filepath.Ext(api.Path()))
	if !ipythonExts[ext] {
		return false
	}
	info, err := api.Stat()
	if err != nil {
		return false
	}
	return e.maxFileSizeBytes <= 0 || info.Size() <= e.maxFileSizeBytes
}

// Extract extracts packages from IPython inline install commands passed through scan input.
func (e Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	ext := strings.ToLower(filepath.Ext(input.Path))
	commands, err := commandsFromReader(input.Reader, ext)
	if err != nil {
		return inventory.Inventory{}, err
	}

	pkgs := []*extractor.Package{}
	for _, command := range commands {
		for _, pkg := range packagesFromCommand(command) {
			pkgs = append(pkgs, &extractor.Package{
				Name:     pkg.name,
				Version:  pkg.version,
				PURLType: purl.TypePyPi,
				Location: extractor.LocationFromPath(input.Path),
			})
		}
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

type notebook struct {
	Cells []struct {
		CellType string      `json:"cell_type"`
		Source   interface{} `json:"source"`
	} `json:"cells"`
}

func commandsFromReader(r io.Reader, ext string) ([]string, error) {
	if ext == ".ipynb" {
		var nb notebook
		if err := json.NewDecoder(r).Decode(&nb); err != nil {
			return nil, err
		}

		var commands []string
		for _, cell := range nb.Cells {
			if cell.CellType != "code" {
				continue
			}
			for _, line := range sourceLines(cell.Source) {
				commands = append(commands, line)
			}
		}
		return commands, nil
	}

	s := bufio.NewScanner(r)
	var commands []string
	for s.Scan() {
		commands = append(commands, s.Text())
	}
	return commands, s.Err()
}

func sourceLines(source interface{}) []string {
	switch v := source.(type) {
	case string:
		return strings.Split(v, "\n")
	case []interface{}:
		var lines []string
		for _, part := range v {
			if s, ok := part.(string); ok {
				lines = append(lines, strings.Split(s, "\n")...)
			}
		}
		return lines
	default:
		return nil
	}
}

type parsedPackage struct {
	name    string
	version string
}

func packagesFromCommand(line string) []parsedPackage {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil
	}
	match := installCmdRe.FindStringSubmatch(trimmed)
	if len(match) < 2 {
		return nil
	}

	tokens := strings.Fields(trimmed)
	if len(tokens) < 3 {
		return nil
	}

	installIdx := -1
	for i := 1; i < len(tokens); i++ {
		if tokens[i] == "install" {
			installIdx = i
			break
		}
	}
	if installIdx == -1 || installIdx+1 >= len(tokens) {
		return nil
	}

	var pkgs []parsedPackage
	for _, tok := range tokens[installIdx+1:] {
		tok = strings.Trim(tok, " \t\r\n,;\"'")
		if tok == "" || strings.HasPrefix(tok, "-") || strings.Contains(tok, "/") || strings.Contains(tok, "://") {
			continue
		}
		if cut, ok := strings.CutPrefix(tok, "conda-forge::"); ok {
			tok = cut
		}
		parts := packageSpecRe.FindStringSubmatch(tok)
		if len(parts) != 4 {
			continue
		}
		if parts[1] == "" {
			continue
		}
		pkgs = append(pkgs, parsedPackage{name: parts[1], version: parts[3]})
	}
	return pkgs
}
