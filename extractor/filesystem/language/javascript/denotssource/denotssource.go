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

// Package denotssource extracts Deno dependencies from TypeScript source files.
package denotssource

import (
	"context"
	"fmt"
	"io"
	"path/filepath"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/denohelper"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/denotssource"
)

// TypeScript file extensions to be processed
var tsExtensions = map[string]bool{
	".ts":   true,
	".tsx":  true,
	".mts":  true,
	".cts":  true,
	".d.ts": true,
}

// Config is the configuration for the Extractor.
type Config struct {
	// MaxFileSizeBytes is the maximum size of a file that can be extracted.
	// If this limit is greater than zero and a file is encountered that is larger
	// than this limit, the file is ignored by returning false for `FileRequired`.
	MaxFileSizeBytes int64
}

// Extractor extracts Deno dependencies from TypeScript source files.
type Extractor struct {
	maxFileSizeBytes int64
}

// New returns a new TypeScript Deno extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{maxFileSizeBytes: cfg.MaxFileSizeBytes}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is a TypeScript file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	// Check for TypeScript files
	if tsExtensions[filepath.Ext(path)] {
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
	path := input.Path

	// Parse TypeScript imports
	// TODO: Why this Typescript file belong to a Deno Project?
	// It need to be a Deno Project, but I don't know how to do it.
	pkgs, err := parseTypeScriptFile(ctx, path, input.Reader)
	if err != nil {
		return inventory.Inventory{},
			fmt.Errorf("error during parsing the typescript file: %w", err)
	}
	for _, p := range pkgs {
		p.Locations = []string{path}
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

func parseTypeScriptFile(ctx context.Context, path string, reader io.Reader) ([]*extractor.Package, error) {
	// Read entire content of TypeScript file
	content, err := io.ReadAll(reader)
	if err != nil {
		log.Debugf("TypeScript file %s read failed: %v", path, err)
		return nil, fmt.Errorf("failed to read TypeScript file: %w", err)
	}
	pkgsStr, err := findImportPathsWithQuery(ctx, content)
	if err != nil {
		return nil, err
	}
	var pkgs []*extractor.Package
	for _, specifier := range pkgsStr {
		pkg := denohelper.ParseImportSpecifier(specifier)
		if pkg != nil {
			pkgs = append(pkgs, pkg)
		}
	}

	// Return any packages found
	return pkgs, nil
}

// findImportPathsWithQuery uses tree-sitter to find import paths in TypeScript source code.
//
// returns a slice of import paths found in the source code.
func findImportPathsWithQuery(ctx context.Context, source []byte) ([]string, error) {
	q, err := sitter.NewQuery([]byte(`
		(import_statement source: (string) @import-source)
		(call_expression function: (import) arguments: (arguments (string) @dynamic-import))
	`), typescript.GetLanguage())
	if err != nil {
		return nil, fmt.Errorf("error while creating query for tree sitter: %w", err)
	}

	// Parse the source
	parser := sitter.NewParser()
	parser.SetLanguage(typescript.GetLanguage())

	tree, err := parser.ParseCtx(context.WithoutCancel(ctx), nil, source)
	if err != nil {
		return nil, fmt.Errorf("error while parsing with tree sitter: %w", err)
	}

	// Create a query cursor
	qc := sitter.NewQueryCursor()
	qc.Exec(q, tree.RootNode())

	// Iterate through matches
	var packages []string
	for {
		// Return if canceled or exceeding the deadline.
		if err := ctx.Err(); err != nil {
			return packages, fmt.Errorf("tree-sitter halted due to context error: %w", err)
		}
		m, ok := qc.NextMatch()
		if !ok {
			break
		}
		// Process captures
		for _, c := range m.Captures {
			capturedText := c.Node.Content(source)
			// Remove quotes from the string
			if len(capturedText) >= 2 && (capturedText[0] == '"' || capturedText[0] == '\'') {
				capturedText = capturedText[1 : len(capturedText)-1]
			}
			packages = append(packages, capturedText)
		}
	}

	return packages, nil
}
