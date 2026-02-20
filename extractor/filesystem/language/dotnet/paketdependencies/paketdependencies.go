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

// Package paketdependencies extracts packages from Paket dependency files (paket.dependencies).
// Paket is a dependency manager for .NET projects.
// See https://fsprojects.github.io/Paket/ for more information.
package paketdependencies

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
	Name = "dotnet/paketdependencies"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	defaultMaxFileSizeBytes = 10 * units.MiB // 10 MB
)

var (
	// Regex to match NuGet package declarations in paket.dependencies
	// Format: nuget PackageName [version constraint]
	// Examples: "nuget NUnit", "nuget NUnit ~> 2.6.3", "nuget NUnit >= 2.6.3"
	reNugetPackage = regexp.MustCompile(`^nuget\s+([^\s]+)(?:\s+(.+))?$`)

	// Regex to match GitHub repository dependencies in paket.dependencies
	// Format: github owner/repo[:commit_hash] [file_path]
	// Examples:
	//   "github fsprojects/Paket"
	//   "github fsprojects/Paket v5.0.0"
	//   "github owner/repo:commit_hash file/path.fs"
	//   "github owner/repo file/path.fs" (no commit)
	reGitHubPackage = regexp.MustCompile(`^github\s+([^\s/]+/[^\s:]+)(?::([^\s]+))?(?:\s+(.+))?$`)
)

// Extractor extracts packages from Paket dependency files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Paket dependencies extractor.
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

// FileRequired returns true if the specified file matches Paket dependency file patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	baseName := filepath.Base(path)

	// Check for paket.dependencies files
	if baseName != "paket.dependencies" {
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

// Extract parses Paket dependency files to extract .NET package dependencies.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	packages, err := e.parseDependenciesFile(input.Reader, input.Path)
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

// parseDependenciesFile parses paket.dependencies files.
// Format: nuget PackageName [version constraint]
func (e Extractor) parseDependenciesFile(reader io.Reader, path string) ([]*extractor.Package, error) {
	var packages []*extractor.Package
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Skip group declarations (groups are optional and not currently extracted as metadata)
		if strings.HasPrefix(line, "group ") {
			continue
		}

		// Skip source declarations
		if strings.HasPrefix(line, "source ") {
			continue
		}

		// Parse NuGet packages
		if matches := reNugetPackage.FindStringSubmatch(line); len(matches) >= 2 {
			pkgName := strings.TrimSpace(matches[1])
			if pkgName == "" {
				continue
			}

			// Extract version if present (version constraints like ~>, >=, ==)
			version := ""
			if len(matches) >= 3 && matches[2] != "" {
				version = extractVersionFromConstraint(matches[2])
			}

			pkg := &extractor.Package{
				Name:      pkgName,
				Version:   version,
				PURLType:  purl.TypeNuget,
				Locations: []string{path},
			}
			packages = append(packages, pkg)
			continue
		}

		// Parse GitHub dependencies
		// Format: github owner/repo[:ref] [version/tag/file_path]
		// Examples:
		//   "github fsprojects/Paket" - just repo
		//   "github fsharp/FAKE v5.20.4" - repo with version
		//   "github owner/repo:2.13.5" - repo with version
		//   "github owner/repo:commit_hash file/path.fs" - repo with commit and file
		//   "github forki/FsUnit FsUnit.fs" - repo with file path (no commit)
		if matches := reGitHubPackage.FindStringSubmatch(line); len(matches) >= 2 {
			repo := strings.TrimSpace(matches[1])
			if repo == "" {
				continue
			}

			commit := ""
			version := ""

			// Group 2 exists if there's a colon - it's a ref that can be either
			// a commit hash or a version/tag.
			// Group 3 exists if there's a space after group 1 or group 2
			hasColon := len(matches) >= 3 && matches[2] != ""
			hasSpaceValue := len(matches) >= 4 && matches[3] != ""

			if hasColon {
				ref := strings.TrimSpace(matches[2])
				// Hex refs are treated as commits (supports abbreviated/full SHAs),
				// otherwise treat as version/tag.
				if len(ref) >= 7 && isHexString(ref) {
					commit = ref
				} else {
					version = ref
				}
				// Group 3 (if exists) is file path, which we ignore
			} else if hasSpaceValue {
				// No colon, so group 3 is the value after space
				// It could be a version/tag or a file path
				spaceValue := strings.TrimSpace(matches[3])
				// If it looks like a version (starts with 'v' or is numeric), treat as version
				// Otherwise, it's probably a file path, which we ignore
				if strings.HasPrefix(spaceValue, "v") ||
					(len(spaceValue) > 0 && spaceValue[0] >= '0' && spaceValue[0] <= '9') {
					version = spaceValue
				}
			}

			// For GitHub dependencies, use the repo as the package name
			// Format: owner/repo
			// Use TypeGithub for GitHub dependencies, not TypeNuget
			sourceCode := &extractor.SourceCodeIdentifier{
				Repo: "https://github.com/" + repo,
			}
			if commit != "" {
				sourceCode.Commit = commit
			}

			pkg := &extractor.Package{
				Name:       repo,
				Version:    version,
				PURLType:   purl.TypeGithub,
				Locations:  []string{path},
				SourceCode: sourceCode,
			}
			packages = append(packages, pkg)
			continue
		}

	}

	if err := scanner.Err(); err != nil {
		log.Errorf("Error parsing Paket dependencies file %s: %v", path, err)
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

// extractVersionFromConstraint extracts a version from a version constraint string.
// Handles constraints like "~> 2.6.3", ">= 2.6.3", "== 2.6.3", "2.6.3"
func extractVersionFromConstraint(constraint string) string {
	constraint = strings.TrimSpace(constraint)

	// Remove constraint operators
	constraint = strings.TrimPrefix(constraint, "~>")
	constraint = strings.TrimPrefix(constraint, ">=")
	constraint = strings.TrimPrefix(constraint, "<=")
	constraint = strings.TrimPrefix(constraint, "==")
	constraint = strings.TrimPrefix(constraint, ">")
	constraint = strings.TrimPrefix(constraint, "<")
	constraint = strings.TrimSpace(constraint)

	// If constraint is empty after removing operators, return empty
	if constraint == "" {
		return ""
	}

	// Extract the first version-like string
	parts := strings.Fields(constraint)
	if len(parts) > 0 {
		return strings.TrimSpace(parts[0])
	}

	return constraint
}

var _ filesystem.Extractor = Extractor{}
