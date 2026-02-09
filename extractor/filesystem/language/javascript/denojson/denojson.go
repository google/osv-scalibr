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

// Package denojson extracts deno.json files.
package denojson

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"deps.dev/util/semver"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/denojson/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/denojson"

	// defaultMaxFileSizeBytes is the default maximum file size the extractor will
	// attempt to extract. If a file is encountered that is larger than this
	// limit, the file is ignored by `FileRequired`.
	defaultMaxFileSizeBytes = 100 * units.MiB

	// Import specifier prefixes
	npmPrefix = "npm:"
	jsrPrefix = "jsr:"
)

// TypeScript file extensions to be processed
var tsExtensions = map[string]bool{
	".ts":   true,
	".tsx":  true,
	".mts":  true,
	".cts":  true,
	".d.ts": true,
}

type denoJSON struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Imports map[string]string `json:"imports"`
}

// Config is the configuration for the Extractor.
type Config struct {
	// MaxFileSizeBytes is the maximum size of a file that can be extracted.
	// If this limit is greater than zero and a file is encountered that is larger
	// than this limit, the file is ignored by returning false for `FileRequired`.
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the deno.json extractor.
func DefaultConfig() Config {
	return Config{
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor extracts javascript packages from deno.json files.
type Extractor struct {
	maxFileSizeBytes int64
}

// New returns a deno.json extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		maxFileSizeBytes: cfg.MaxFileSizeBytes,
	}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches javascript Metadata file
// patterns or is a TypeScript file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()

	// Check for deno.json files
	if filepath.Base(path) == "deno.json" {
		fileinfo, err := api.Stat()
		if err != nil {
			return false
		}
		if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
			return false
		}
		return true
	}

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

// Extract extracts packages from deno.json or TypeScript files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	path := input.Path

	// Parse TypeScript files
	if tsExtensions[filepath.Ext(path)] {
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

	// Parse deno.json files
	if filepath.Base(path) == "deno.json" {
		pkgs, err := parseDenoJsonFile(path, input.Reader)
		if err != nil {
			return inventory.Inventory{},
				fmt.Errorf("error during parsing the deno.json: %w", err)
		}

		for _, p := range pkgs {
			p.Locations = []string{path}
		}

		return inventory.Inventory{Packages: pkgs}, nil
	}
	return inventory.Inventory{}, nil
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
		pkg := parseImportSpecifier(specifier)
		if pkg != nil {
			pkgs = append(pkgs, pkg)
		}
	}

	// Return any packages found
	return pkgs, nil
}

func parseDenoJsonFile(path string, r io.Reader) ([]*extractor.Package, error) {
	dec := json.NewDecoder(r)

	var p denoJSON
	if err := dec.Decode(&p); err != nil {
		log.Debugf("deno.json file %s json decode failed: %v", path, err)
		return nil, fmt.Errorf("failed to parseDenoJsonFile deno.json file: %w", err)
	}

	if !p.hasNameAndVersionValues() {
		log.Debugf("deno.json file %s does not have a version and/or name", path)
		return nil, nil
	}

	var pkgs []*extractor.Package
	// TODO: should we include the package itself?
	//pkgs = append(pkgs, &extractor.Package{
	//	Name:     p.Name,
	//	Version:  p.Version,
	//	PURLType: purl.TypeNPM,
	//	Metadata: &metadata.JavascriptDenoJSONMetadata{},
	//})

	if len(p.Imports) > 0 {
		for _, importSpec := range p.Imports {
			pkg := parseImportSpecifier(importSpec)
			if pkg != nil {
				pkgs = append(pkgs, pkg)
			}
		}
	}

	return pkgs, nil
}

func parseImportSpecifier(specifier string) *extractor.Package {
	// Handle npm: prefixed imports (e.g., "npm:chalk@1")
	if strings.HasPrefix(specifier, npmPrefix) {
		pkgSpecifier := strings.TrimPrefix(specifier, npmPrefix)
		packageName, packageVersion := parseNPMNameAndVersion(pkgSpecifier)
		v, valid := checkNPMNameAndVersion(packageName, packageVersion)
		if !valid {
			return nil
		} else if v != "" {
			return &extractor.Package{
				Name:     packageName,
				Version:  v,
				PURLType: purl.TypeNPM,
				Metadata: &metadata.JavascriptDenoJSONMetadata{
					URL: specifier,
				},
			}
		}
	}
	// Handle jsr: prefixed imports (e.g., "jsr:@std1/path1@^1")
	if strings.HasPrefix(specifier, jsrPrefix) {
		pkgSpecifier := strings.TrimPrefix(specifier, jsrPrefix)
		name, version := parseJSRNameAndVersion(pkgSpecifier)
		if name != "" && version != "" {
			return &extractor.Package{
				Name:     name,
				Version:  version,
				PURLType: purl.TypeJSR,
				Metadata: &metadata.JavascriptDenoJSONMetadata{
					URL: specifier,
				},
			}
		}
	}
	// Handle https:// URLs
	if strings.HasPrefix(specifier, "https://") {
		return parseHTTPSURL(specifier)
	}
	return nil
}

// parseHTTPSURL parses HTTPS URLs and extracts package information from various CDN hosts.
func parseHTTPSURL(specifier string) *extractor.Package {
	parsedURL, err := url.Parse(specifier)
	if err != nil {
		log.Debugf("failed to parse URL %s: %v", specifier, err)
		return nil
	}

	host := parsedURL.Host
	path := parsedURL.Path
	if path != "" && path[0] == '/' {
		path = path[1:] // Remove the leading slash
	}

	// Handle esm.sh imports
	if host == "esm.sh" {
		var packageName, packageVersion, purlType string

		// JSR imports (starts with /jsr/)
		if strings.HasPrefix(path, "jsr/") {
			// Example: https://esm.sh/jsr/@std/encoding@1.0.0/base64
			jsrPath := strings.TrimPrefix(path, "jsr/")
			packageName, packageVersion = parseJSRNameAndVersion(jsrPath)
			purlType = purl.TypeJSR
			// GitHub imports (starts with /gh/)
		} else if strings.HasPrefix(path, "gh/") {
			// Example: https://esm.sh/gh/microsoft/tslib@v2.8.0
			ghPath := strings.TrimPrefix(path, "gh/")
			parts := strings.Split(ghPath, "@")
			if len(parts) == 2 {
				packageName = parts[0]
				packageVersion = parts[1]
			}
			purlType = purl.TypeGithub
			// Default URL is NPM import
			// (e.g., "https://esm.sh/canvas-confetti@1.6.0")
		} else {
			packageName, packageVersion = parseNPMNameAndVersion(path)
			purlType = purl.TypeNPM
		}

		if packageName != "" && packageVersion != "" {
			return &extractor.Package{
				Name:     packageName,
				Version:  packageVersion,
				PURLType: purlType,
				Metadata: &metadata.JavascriptDenoJSONMetadata{
					FromESMCDN: true,
					URL:        specifier,
				},
			}
		}
	}

	// Handle deno.land/x imports (e.g., "https://deno.land/x/openai@v4.69.0/mod.ts")
	if host == "deno.land" && strings.HasPrefix(path, "x/") {
		// Extract the package name and version from a path
		packageName, packageVersion := parseNPMNameAndVersion(strings.TrimPrefix(path, "x/"))
		if packageName != "" && packageVersion != "" {
			return &extractor.Package{
				Name:     packageName,
				Version:  packageVersion,
				PURLType: purl.TypeNPM,
				Metadata: &metadata.JavascriptDenoJSONMetadata{
					FromDenolandCDN: true,
					URL:             specifier,
				},
			}
		}
	}

	// Handle unpkg.com imports (e.g., "https://unpkg.com/lodash-es@4.17.21/lodash.js")
	if host == "unpkg.com" {
		if path == "" {
			return nil
		}
		packageName, packageVersion := parseNPMNameAndVersion(path)
		if packageName != "" && packageVersion != "" {
			return &extractor.Package{
				Name:     packageName,
				Version:  packageVersion,
				PURLType: purl.TypeNPM,
				Metadata: &metadata.JavascriptDenoJSONMetadata{
					FromUnpkgCDN: true,
					URL:          specifier,
				},
			}
		}
	}

	return nil
}

// parseNPMNameAndVersion parses the name and version from a npm package specifier.
// Handles both regular packages (e.g., "chalk@1") and scoped packages (e.g., "@types/node@14").
// Removes paths after the version (e.g., "chalk@1.0.0/dist/index.js").
// Trims the char "v" before the version
func parseNPMNameAndVersion(specifier string) (name, version string) {
	if strings.HasPrefix(specifier, "@") {
		specifier = strings.TrimPrefix(specifier, "@")
	}
	// Extract the package name and version from the path
	packageParts := strings.SplitN(specifier, "@", 2)
	var extractedName, extractedVersion string
	if len(packageParts) == 2 {
		extractedName = packageParts[0]
		extractedVersion = packageParts[1]
		if strings.HasPrefix(extractedVersion, "v") {
			extractedVersion = strings.TrimPrefix(extractedVersion, "v")
		}
		// Require the version to start with a numeric value
		if !regexp.MustCompile(`^\d`).MatchString(extractedVersion) {
			return "", ""
		}
		// Strip any trailing path after the version
		if idx := strings.Index(extractedVersion, "/"); idx != -1 {
			extractedVersion = extractedVersion[:idx]
		}
	}
	if len(packageParts) == 1 {
		return packageParts[0], ""
	}
	return extractedName, extractedVersion
}

// parseJSRNameAndVersion parses the name and version from a JSR package specifier.
// Handles both regular packages and scoped packages (e.g., "@std/path@^1").
func parseJSRNameAndVersion(specifier string) (name, version string) {
	if strings.HasPrefix(specifier, "@") {
		specifier = strings.TrimPrefix(specifier, "@")
	}
	parts := strings.SplitN(specifier, "@", 2)
	// "std/encoding@1.0.0/base64"
	if len(parts) == 2 {
		if strings.Contains(parts[1], "/") {
			return parts[0], strings.Split(parts[1], "/")[0]
		} else {
			return parts[0], parts[1]
		}
	}
	return "", ""
}

func (p denoJSON) hasNameAndVersionValues() bool {
	return p.Name != "" && p.Version != ""
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

	tree, err := parser.ParseCtx(context.Background(), nil, source)
	if err != nil {
		return nil, fmt.Errorf("error while parsing with tree sitter: %w", err)
	}

	// Create a query cursor
	qc := sitter.NewQueryCursor()
	qc.Exec(q, tree.RootNode())

	// Iterate through matches
	var packages []string
	for {
		// Return if canceled or exceeding deadline.
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

// checkNPMNameAndVersion checks if the NPM Package name is not empty and the version is a valid semver constraint.
func checkNPMNameAndVersion(name, version string) (string, bool) {
	if name == "" || version == "" {
		return "", false
	}

	c, err := semver.NPM.ParseConstraint(version)
	if err != nil {
		log.Debugf("failed to parse NPM version constraint %s for dependency %s: %v", version, name, err)
		return "", false
	}

	v, err := c.CalculateMinVersion()
	if err != nil {
		log.Debugf("failed to calculate min NPM version for dependency %s with constraint %s: %v", name, version, err)
		return "", false
	}

	return v.Canon(false), true
}
