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

// Package paketlock extracts packages from Paket lock files (paket.lock).
// Paket is a dependency manager for .NET projects.
// See https://fsprojects.github.io/Paket/ for more information.
package paketlock

import (
	"bufio"
	"context"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "dotnet/paketlock"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	defaultMaxFileSizeBytes = 10 * units.MiB // 10 MB
)

var (
	// Regex to match package entries in paket.lock
	// Format: PackageName (version)
	// Example: "    NUnit (2.6.3)" - exactly 4 spaces for top-level packages
	// Note: We only match top-level packages (not indented dependency constraints)
	// The regex requires exactly 4 spaces followed by a non-space character
	reLockPackage = regexp.MustCompile(`^    ([^\s(]+)\s*\(([^)]+)\)`)

	// Regex to match GitHub entries with file path and commit hash
	// Format: filepath.fs (commit_hash)
	// Example: "    src/app/FakeLib/Globbing/Globbing.fs (0341a2e614eb2a7f34607cec914eb0ed83ce9add)"
	reGitHubLockEntry = regexp.MustCompile(`^    (.+?)\s+\(([^)]+)\)`)
)

// Extractor extracts packages from Paket lock files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Paket lock extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.DotnetPaketConfig {
		return c.GetDotnetPaket()
	})
	if specific != nil && specific.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = specific.GetMaxFileSizeBytes()
	}

	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches Paket lock file patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	baseName := filepath.Base(path)

	// Check for paket.lock files
	if baseName != "paket.lock" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil || (e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes) {
		e.reportFileRequired(path, stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, result stats.FileRequiredResult) {
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:   path,
		Result: result,
	})
}

// Extract parses Paket lock files to extract .NET package dependencies.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	packages, err := e.parseLockFile(input.Reader, input.Path)
	if e.Stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inventory.Inventory{Packages: packages}, err
}

// parseLockFile parses paket.lock files.
// Format: PackageName (version)
// Only extracts top-level packages, not indented dependency constraints.
func (e Extractor) parseLockFile(reader io.Reader, path string) ([]*extractor.Package, error) {
	var packages []*extractor.Package
	scanner := bufio.NewScanner(reader)

	var currentSection string    // Track current section
	var currentGitHubRepo string // Track current GitHub repo from remote: line

	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines and comments
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Detect section headers
		// Section headers are uppercase words with no indentation at the start of a line
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			switch trimmed {
			case "NUGET", "GITHUB", "GIST", "HTTP", "FRAMEWORK", "RESTRICTION":
				currentSection = trimmed
				currentGitHubRepo = "" // Reset when entering new section
				continue
			}
		}

		// Handle remote: lines in GITHUB section to track the repo name
		if strings.HasPrefix(trimmed, "remote:") {
			if currentSection == "GITHUB" {
				// Extract repo from "remote: owner/repo"
				parts := strings.Fields(trimmed)
				if len(parts) >= 2 {
					currentGitHubRepo = strings.TrimSpace(parts[1])
				}
			}
			continue
		}

		// Only extract top-level packages (indented with exactly 4 spaces)
		// Skip lines with no indentation (section headers) or more than 4 spaces (transitive dependencies)
		// Check: line must start with exactly 4 spaces, and the 5th character must NOT be a space
		if !strings.HasPrefix(line, "    ") {
			continue
		}
		// Skip lines with more than 4 spaces (transitive dependencies have 6+ spaces)
		// After 4 spaces, the next character should be the package name (non-space)
		if len(line) > 4 && (line[4] == ' ' || line[4] == '\t') {
			continue
		}

		// Parse package entries: PackageName (version)
		// Format: "    PackageName (version)" - exactly 4 spaces for top-level packages
		matches := reLockPackage.FindStringSubmatch(line)
		if len(matches) >= 3 {
			// Only process dependency entries from sections we support.
			// Explicitly skip GIST/HTTP sections.
			if currentSection != "NUGET" && currentSection != "GITHUB" {
				continue
			}

			pkgName := strings.TrimSpace(matches[1])
			version := strings.TrimSpace(matches[2])

			if pkgName == "" || version == "" {
				continue
			}

			// Skip dependency constraints (versions with >=, <=, >, <, ~>, etc.)
			// Lock files should only contain resolved versions (numeric versions)
			if strings.ContainsAny(version, "><=~") {
				continue
			}

			// Handle GitHub dependencies differently
			if currentSection == "GITHUB" {
				// For GitHub dependencies in lock files, there are two formats:
				// 1. Simple: "    repo/name (version/tag)" - package name matches repo
				// 2. With file: "    file/path.fs (commit)" - package name is file path, repo from remote: line
				repoName := currentGitHubRepo
				commit := ""
				pkgVersion := ""

				if repoName == "" {
					// No remote: line tracked, so pkgName is the repo name (simple format)
					repoName = pkgName
					// In simple format, version could be a tag/version or commit hash
					// If it's 40 hex chars, it's a commit; otherwise it's a version tag
					if len(version) == 40 && isHexString(version) {
						commit = version
					} else {
						pkgVersion = version
					}
				} else if pkgName == repoName {
					// Package name matches repo name - this is the simple format
					// The value could be a version tag or commit hash
					if len(version) == 40 && isHexString(version) {
						commit = version
					} else {
						pkgVersion = version
					}
				} else {
					// Package name doesn't match repo - it's a file path
					// The value in parentheses is the commit hash
					commit = version
				}

				sourceCode := &extractor.SourceCodeIdentifier{
					Repo: "https://github.com/" + repoName,
				}
				if commit != "" {
					sourceCode.Commit = commit
				}

				pkg := &extractor.Package{
					Name:       repoName,
					Version:    pkgVersion,
					PURLType:   purl.TypeGithub,
					Locations:  []string{path},
					SourceCode: sourceCode,
				}
				packages = append(packages, pkg)
			} else {
				// NuGet and other package types
				pkg := &extractor.Package{
					Name:      pkgName,
					Version:   version,
					PURLType:  purl.TypeNuget,
					Locations: []string{path},
				}
				packages = append(packages, pkg)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Errorf("Error parsing Paket lock file %s: %v", path, err)
		return nil, err
	}

	if packages == nil {
		packages = []*extractor.Package{}
	}
	return packages, nil
}

// isHexString checks if a string contains only hexadecimal characters.
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

var _ filesystem.Extractor = Extractor{}
