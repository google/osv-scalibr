// Package config implementation of the MCP (Model Context Protocol) extractor.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/mcp/config/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	Name           = "mcp/config"
	defaultVersion = 0
)

type Extractor struct{}

// New creates a new MCP Config extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{}, nil
}

// Name returns the name of the extractor.
func (e *Extractor) Name() string { return Name }

// Version returns the version of the extractor.
func (e *Extractor) Version() int { return defaultVersion }

// Requirements returns the requirements for the extractor.
func (e *Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// DefaultExclusions is the list of directories to ignore.
var DefaultExclusions = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"__pycache__":  true,
	"venv":         true,
	".venv":        true,
	"target":       true, // Rust
	"dist":         true,
	"build":        true,
	".next":        true,
	".terraform":   true,
	".gradle":      true,
}

// FileRequired returns true if the file is an MCP configuration file.
// We look for:
//   - mcp.json
//   - .mcp.json
//   - mcp-servers.json
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	base := filepath.Base(path)

	// Case-insensitive match for standard filenames
	lowerBase := strings.ToLower(base)
	if lowerBase != "mcp.json" && lowerBase != ".mcp.json" && lowerBase != "mcp-servers.json" {
		return false
	}

	// Check for ignored directories in the path
	if shouldSkip(path) {
		return false
	}

	return true
}

// Extract parses the MCP configuration file and returns the inventory.
func (e *Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	// 1. Parse JSON
	var manifest Manifest
	decoder := json.NewDecoder(input.Reader)
	if err := decoder.Decode(&manifest); err != nil {
		// If JSON is malformed, we just return empty/error.
		return inventory.Inventory{}, fmt.Errorf("failed to decode JSON: %w", err)
	}

	// 2. Validation: A file is only considered a match if it contains a top-level
	// mcpServers key.
	if len(manifest.MCPServers) == 0 {
		return inventory.Inventory{}, nil
	}

	inv := &inventory.Inventory{}

	for name, server := range manifest.MCPServers {
		serverPkg := &extractor.Package{
			Name:      name,
			Locations: []string{input.Path},
		}

		// 3. PURL Generation
		purlType, purlName, purlVersion := determinePURL(name, server.Command, server.Args)

		// Apply PURL if we found a valid type
		if purlType != "" && purlName != "" {
			serverPkg.PURLType = purlType
			serverPkg.Name = purlName
			serverPkg.Version = purlVersion
		}

		// 4. Metadata & Redaction
		// Mandatory Secret Redaction: Scrub env block.
		redactedEnv := make(map[string]string)
		for k := range server.Env {
			redactedEnv[k] = "[REDACTED]"
		}

		// Path Normalization: Resolve relative paths in args relative to manifest location.
		manifestDir := filepath.Dir(input.Path)
		normalizedArgs := make([]string, len(server.Args))
		for i, arg := range server.Args {
			if strings.HasPrefix(arg, ".") {
				normalizedArgs[i] = filepath.Join(manifestDir, arg)
			} else {
				normalizedArgs[i] = arg
			}
		}

		// Store metadata
		serverPkg.Metadata = &metadata.Metadata{
			Command:   server.Command,
			Args:      normalizedArgs,
			Env:       redactedEnv,
			RuntimeID: name, // Stores the original JSON key
		}

		inv.Packages = append(inv.Packages, serverPkg)
	}

	return *inv, nil
}

// Manifest represents the structure of an mcp.json file.
type Manifest struct {
	MCPServers map[string]ServerConfig `json:"mcpServers"`
}

// ServerConfig represents a single server configuration in the manifest.
type ServerConfig struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
}

// determinePURL determines the PURL components based on the server command and args.
func determinePURL(serverName, command string, args []string) (string, string, string) {
	purlType := ""
	purlName := ""
	purlVersion := ""

	cmd := strings.ToLower(command)

	// NPM (npx)
	if cmd == "npx" && len(args) > 0 {
		purlType = purl.TypeNPM
		pkgArg := firstNonFlagArg(args)
		if pkgArg != "" {
			purlName, purlVersion = splitPackageVersion(pkgArg)
		}

		// PyPI (uvx, pip)
	} else if (cmd == "uvx" || cmd == "pip") && len(args) > 0 {
		purlType = purl.TypePyPi
		// uvx package-name
		pkgArg := firstNonFlagArg(args)
		if pkgArg != "" {
			purlName, purlVersion = splitPackageVersion(pkgArg)
		}

		// Fallback / Generic Binaries
	} else {
		// It is a raw binary, script, or docker command.
		// We classify this as 'generic' and namespace it under 'mcp-server'.
		purlType = purl.TypeGeneric
		purlName = "mcp-server/" + serverName
	}
	return purlType, purlName, purlVersion
}

// Helper to find the first non-flag argument.
func firstNonFlagArg(args []string) string {
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			return arg
		}
	}
	return ""
}

// splitPackageVersion splits package name and version (e.g. pkg@1.2.3 -> pkg, 1.2.3)
func splitPackageVersion(arg string) (string, string) {
	// Check for @
	lastAt := strings.LastIndex(arg, "@")
	if lastAt > 0 { // > 0 to avoid matching @scope (start of string)
		// careful with scoped packages @scope/pkg
		// If it starts with @, we need to make sure we don't split the scope.
		// Scoped package with version: @scope/pkg@1.2.3 -> lastAt will be correct.
		// Scoped package without version: @scope/pkg -> lastAt will be 0.
		return arg[:lastAt], arg[lastAt+1:]
	}
	return arg, ""
}

// shouldSkip checks if the path contains any ignored directories.
func shouldSkip(path string) bool {
	dir := filepath.Dir(path)

	current := dir
	for {
		if current == "." || current == "/" || current == "\\" || current == "" {
			break
		}
		base := filepath.Base(current)
		if DefaultExclusions[base] {
			return true
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return false
}
