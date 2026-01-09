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

// Package peversion extracts product names and versions from Windows PE executables and DLLs.
// This extractor parses PE version resources from .exe and .dll files and emits packages
// with product name and version information.
package peversion

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/saferwall/pe"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/peversion"
	// Maximum file size to parse (300 MB).
	maxFileSizeBytes = 300 * 1024 * 1024
)

// Precompiled regex patterns for filename parsing.
var (
	archRegex = regexp.MustCompile(`(?i)(x64|x86|arm64|arm32|portable)`)
	verRegex  = regexp.MustCompile(`(\d+[\._-]?\d*)`)
)

// Common Windows system directories that typically contain many PE files
// but are less relevant for security scanning.
var systemDirFragments = []string{
	string(os.PathSeparator) + "Windows" + string(os.PathSeparator) + "System32",
	string(os.PathSeparator) + "Windows" + string(os.PathSeparator) + "WinSxS",
	string(os.PathSeparator) + "Windows" + string(os.PathSeparator) + "Servicing",
	string(os.PathSeparator) + "Windows" + string(os.PathSeparator) + "SoftwareDistribution",
}

// Config configures the PE version extractor behavior.
type Config struct {
	// SkipSystemDirs, if true, skips common Windows system directories
	// like System32, WinSxS to reduce noise and scan time.
	SkipSystemDirs bool
}

// DefaultConfig returns the recommended default configuration.
func DefaultConfig() Config {
	return Config{
		SkipSystemDirs: true,
	}
}

// Extractor extracts product names and versions from Windows PE files.
type Extractor struct {
	config Config
}

// New creates a new PE version extractor with the given configuration.
func New(config Config) filesystem.Extractor {
	return &Extractor{config: config}
}

// NewDefault returns an extractor with default configuration.
func NewDefault() filesystem.Extractor {
	return New(DefaultConfig())
}

// Name of the extractor.
func (Extractor) Name() string { return Name }

// Version of the extractor.
func (Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		OS:            plugin.OSWindows,
		DirectFS:      true,
		RunningSystem: true,
	}
}

// FileRequired returns true if the file is a PE executable (.exe or .dll)
// that should be scanned for version information.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()

	// Only process .exe and .dll files.
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".exe" && ext != ".dll" {
		return false
	}

	// Skip common Windows system directories if configured.
	if e.config.SkipSystemDirs && shouldSkipSystemDir(path) {
		log.Debugf("peversion: Skipping system directory file: %q", path)
		return false
	}

	// Skip files that are too large.
	info, err := api.Stat()
	if err != nil {
		log.Debugf("peversion: Could not stat file %q: %v", path, err)
		return false
	}
	if info.Size() > maxFileSizeBytes {
		log.Debugf("peversion: Skipping large file %q (%d bytes)", path, info.Size())
		return false
	}

	return true
}

// Extract extracts package information from a PE file.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	// Check for context cancellation.
	if err := ctx.Err(); err != nil {
		return inventory.Inventory{}, err
	}

	// Get the real filesystem path for PE parsing.
	// The PE library needs direct file access, not a reader.
	absPath, err := input.GetRealPath()
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("GetRealPath(%v): %w", input, err)
	}

	// Clean up temporary file if created.
	if input.Root == "" {
		defer func() {
			dir := filepath.Dir(absPath)
			if err := os.RemoveAll(dir); err != nil {
				log.Debugf("peversion: Failed to clean up temporary directory %s: %v", dir, err)
			}
		}()
	}

	// Extract version and product name from PE resources.
	version, prodName, peMetadata := extractPEVersionWithMetadata(absPath)
	log.Debugf("peversion: Extracted PE metadata - version: %q, prodName: %q, metadata: %v", version, prodName, peMetadata)

	if prodName == "" {
		// No useful product name found, skip this file.
		log.Debugf("peversion: Skipping %q - no product name found", input.Path)
		return inventory.Inventory{}, nil
	}

	normalizedVersion := normalizeVersion(version)
	log.Debugf("peversion: Found PE package: %q (version: %q) at %q", prodName, normalizedVersion, input.Path)

	// Create metadata map with PE version resource information.
	metadata := map[string]any{
		"original_path": input.Path,
		"raw_version":   version,
	}
	// Add PE version resource metadata if available.
	for key, value := range peMetadata {
		metadata["pe_"+key] = value
	}

	pkg := &extractor.Package{
		Name:       prodName,
		Version:    normalizedVersion,
		PURLType:   purl.TypeGeneric,
		Locations:  []string{input.Path},
		Metadata:   metadata,
		SourceCode: &extractor.SourceCodeIdentifier{},
	}

	return inventory.Inventory{Packages: []*extractor.Package{pkg}}, nil
}

// shouldSkipSystemDir checks if a path contains common system directories.
func shouldSkipSystemDir(path string) bool {
	lowerPath := strings.ToLower(path)
	for _, frag := range systemDirFragments {
		if strings.Contains(lowerPath, strings.ToLower(frag)) {
			return true
		}
	}
	return false
}

// extractPEVersionWithMetadata extracts version information, product name, and additional
// PE resource metadata. It returns the version string, product name, and a map of
// additional version resource fields. If parsing fails, it falls back to filename-based heuristics.
func extractPEVersionWithMetadata(exePath string) (version, prodName string, metadata map[string]string) {
	metadata = make(map[string]string)

	peFile, err := pe.New(exePath, &pe.Options{})
	if err != nil {
		// PE parsing failed, try filename heuristics.
		version, prodName = extractVersionFromFilename(exePath)
		return
	}
	defer peFile.Close()

	// Parse the PE file structure.
	if err = peFile.Parse(); err != nil {
		version, prodName = extractVersionFromFilename(exePath)
		return
	}

	// Extract version resources.
	versionInfo, err := peFile.ParseVersionResources()
	if err != nil {
		version, prodName = extractVersionFromFilename(exePath)
		return
	}

	// Extract version: prefer ProductVersion, fallback to FileVersion.
	if productVersion, ok := versionInfo["ProductVersion"]; ok && productVersion != "" {
		version = productVersion
	} else if fileVersion, ok := versionInfo["FileVersion"]; ok && fileVersion != "" {
		version = fileVersion
	}

	// Extract product name: prefer ProductName, fallback to InternalName or OriginalFilename.
	if productName, ok := versionInfo["ProductName"]; ok && productName != "" {
		prodName = productName
	} else if internalName, ok := versionInfo["InternalName"]; ok && internalName != "" {
		prodName = internalName
	} else if originalFilename, ok := versionInfo["OriginalFilename"]; ok && originalFilename != "" {
		prodName = originalFilename
	}

	// Store additional PE version resource fields for security analysis.
	interestingFields := []string{
		"CompanyName", "LegalCopyright", "FileDescription",
		"OriginalFilename", "InternalName", "LegalTrademarks",
		"PrivateBuild", "SpecialBuild", "Comments",
	}

	for _, field := range interestingFields {
		if value, ok := versionInfo[field]; ok && value != "" {
			metadata[field] = value
		}
	}

	// If PE parsing didn't yield version, try filename heuristics.
	if version == "" {
		fallbackVersion, _ := extractVersionFromFilename(exePath)
		version = fallbackVersion
	}

	// If no product name found in PE resources, use the base filename as fallback.
	if prodName == "" {
		base := filepath.Base(exePath)
		// Remove file extension to get a cleaner product name.
		prodName = strings.TrimSuffix(base, filepath.Ext(base))
	}

	return version, prodName, metadata
}

// extractVersionFromFilename attempts to extract version from the filename.
// This is a fallback method when PE resource parsing fails.
// Note: This method only extracts version, not product name, as filenames
// are unreliable for product identification.
func extractVersionFromFilename(exePath string) (version, prodName string) {
	base := filepath.Base(exePath)
	lower := strings.ToLower(base)

	// Remove architecture markers and file extensions for version extraction.
	clean := archRegex.ReplaceAllString(lower, "")
	clean = strings.TrimSuffix(clean, ".exe")
	clean = strings.TrimSuffix(clean, ".dll")

	// Try to find a version number pattern.
	// Only extract versions that have clear delimiters (dots, underscores, hyphens).
	verMatch := verRegex.FindStringSubmatch(clean)
	if verMatch != nil {
		verStr := verMatch[1]
		// Only use version if it contains a delimiter, making it unambiguous.
		// e.g., "6.10", "6_10", "6-10" are valid; "610" is ambiguous and skipped.
		if strings.ContainsAny(verStr, "._-") {
			// Replace underscores and hyphens with dots.
			version = strings.ReplaceAll(verStr, "_", ".")
			version = strings.ReplaceAll(version, "-", ".")
		}
	}

	// Return empty product name - filenames are too unreliable for product identification.
	// However, provide filename as product name if we found a version (increases confidence).
	if version != "" {
		baseName := strings.TrimSuffix(base, filepath.Ext(base))
		prodName = baseName
	}

	return version, prodName
}

// normalizeVersion standardizes version strings by replacing common separators with dots.
func normalizeVersion(ver string) string {
	ver = strings.TrimSpace(ver)
	ver = strings.ReplaceAll(ver, "_", ".")
	ver = strings.ReplaceAll(ver, "-", ".")
	return ver
}

// Ensure Extractor implements the filesystem.Extractor interface.
var _ filesystem.Extractor = (*Extractor)(nil)
