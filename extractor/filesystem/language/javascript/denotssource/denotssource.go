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

// Package denotssource extracts Deno dependencies from TypeScript source files.
package denotssource

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/denohelper"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/internal/linefinder"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/denotssource"
)

var (
	// TypeScript file extensions to be processed
	tsExtensions = map[string]bool{
		".ts":   true,
		".tsx":  true,
		".mts":  true,
		".cts":  true,
		".d.ts": true,
	}

	// Regexps for typescript import statements that capture imported package name.
	// e.g. import {debounce} from "https://unpkg.com/lodash-es@4.17.21/lodash.js";
	importRe = regexp.MustCompile(`\bimport\s*.*\s*from\s*"(.*)"`)
	// e.g. await import("https://unpkg.com/lodash-es@4.17.22/lodash.js");
	dynamicImportRe = regexp.MustCompile(`\bimport\(\s*"(.*)"\s*\)`)
)

// Extractor extracts Deno dependencies from TypeScript source files.
type Extractor struct {
	maxFileSizeBytes       int64
	maxDenoJSONSearchDepth int
}

// New returns a new TypeScript Deno extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxSize := cfg.MaxFileSizeBytes
	maxDenoJSONSearchDepth := 2
	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.DenoTSSourceConfig { return c.GetDenotssource() })
	if specific.GetMaxFileSizeBytes() > 0 {
		maxSize = specific.GetMaxFileSizeBytes()
	}
	if specific.GetDenoJsonSearchDepthLevel() > 0 {
		maxDenoJSONSearchDepth = int(specific.GetDenoJsonSearchDepthLevel())
	}
	return &Extractor{maxFileSizeBytes: maxSize, maxDenoJSONSearchDepth: maxDenoJSONSearchDepth}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is a TypeScript file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	inputPath := api.Path()
	// Check for TypeScript files
	if tsExtensions[path.Ext(inputPath)] {
		fileinfo, err := api.Stat()
		if err != nil {
			return false
		}
		if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
			return false
		}
		return true
	}

	return false
}

// Extract extracts packages from TypeScript source files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	inputPath := input.Path

	// Check if this TypeScript file is part of a Deno project by looking for
	// deno.json or deno.lock in ancestor directories.
	if !hasDenoConfigInAncestors(input.FS, inputPath, e.maxDenoJSONSearchDepth) {
		log.Debugf("Skipping TypeScript file %s: no deno.json or deno.lock found in ancestor directories", inputPath)
		return inventory.Inventory{}, nil
	}

	// Parse TypeScript imports
	pkgs, err := parseTypeScriptFile(ctx, inputPath, input.Reader)
	if err != nil {
		return inventory.Inventory{},
			fmt.Errorf("error during parsing the typescript file: %w", err)
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

// hasDenoConfigInAncestors checks if a deno.json or deno.lock file exists in any
// ancestor directory of the given path, up to maxDepth levels.
func hasDenoConfigInAncestors(fsys scalibrfs.FS, inputPath string, maxDepth int) bool {
	dir := path.Dir(inputPath)
	for range maxDepth {
		if _, err := fs.Stat(fsys, path.Join(dir, "deno.json")); err == nil {
			return true
		}
		if _, err := fs.Stat(fsys, path.Join(dir, "deno.lock")); err == nil {
			return true
		}
		parent := path.Dir(dir)
		if parent == dir {
			// Reached the root
			break
		}
		dir = parent
	}
	return false
}

func parseTypeScriptFile(ctx context.Context, inputPath string, reader io.Reader) ([]*extractor.Package, error) {
	// Read entire content of TypeScript file
	content, err := io.ReadAll(reader)
	if err != nil {
		log.Debugf("TypeScript file %s read failed: %v", inputPath, err)
		return nil, fmt.Errorf("failed to read TypeScript file: %w", err)
	}
	importPaths, err := findImportPaths(ctx, content)
	if err != nil {
		return nil, err
	}
	var pkgs []*extractor.Package
	for _, ip := range importPaths {
		pkg := denohelper.ParseImportSpecifier(ip.specifier)
		if pkg != nil {
			pkg.Location = extractor.LocationFromPathAndLine(inputPath, ip.line)
			pkgs = append(pkgs, pkg)
		}
	}

	// Return any packages found
	return pkgs, nil
}

// importPath represents a matched import and its line number.
type importPath struct {
	// specifier is the raw import specifier (e.g. "npm:cowsay@1.6.0").
	specifier string
	// line is the line number where this import was found.
	line int
}

// findImportPaths uses regexps to find import paths in TypeScript source code.
func findImportPaths(ctx context.Context, source []byte) ([]importPath, error) {
	var results []importPath
	finder := linefinder.NewOffsetFinder(source)

	for _, re := range []*regexp.Regexp{importRe, dynamicImportRe} {
		// Use FindAllSubmatchIndex to get [start, end, sub_start, sub_end]
		//
		// Example index mapping for: `import { cowsay } from "npm:cowsay@1.6.0";`
		// - match[0] = 0, match[1] = 42 (entire statement bounds)
		// - match[2] = 25, match[3] = 41 (specifier "npm:cowsay@1.6.0" bounds)
		matches := re.FindAllSubmatchIndex(source, -1)
		for _, match := range matches {
			if err := ctx.Err(); err != nil {
				return results, err
			}
			if len(match) < 4 {
				continue
			}
			// match[2] and match[3] are the start and end byte offsets of the first capturing group (the import specifier).
			specifier := string(source[match[2]:match[3]])
			results = append(results, importPath{
				specifier: specifier,
				// match[0] is the start byte offset of the entire match (the "import" statement).
				line: finder.LineOfOffset(match[0]),
			})
		}
	}
	return results, nil
}
