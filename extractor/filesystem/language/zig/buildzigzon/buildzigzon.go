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

// Package buildzigzon extracts build.zig.zon files from installed and depended Zig packages.
package buildzigzon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "zig/buildzigzon"

	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 30 * units.MiB
)

// Extractor extracts Zig package info from build.zig.zon files.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
	// Flag for determining mode, artifact or source code scanning
	scanDependencies bool
}

// NewWithDeps returns a Zig build.zig.zon source code extractor.
func NewWithDeps(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.ZigBuildZigZonConfig { return c.GetBuildzigzon() })
	if specific.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = specific.GetMaxFileSizeBytes()
	}

	return &Extractor{maxFileSizeBytes: maxFileSizeBytes, scanDependencies: true}, nil
}

// New returns a Zig build.zig.zon artifact extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.ZigBuildZigZonConfig { return c.GetBuildzigzon() })
	if specific.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = specific.GetMaxFileSizeBytes()
	}

	return &Extractor{maxFileSizeBytes: maxFileSizeBytes, scanDependencies: specific.GetScanDependencies()}, nil
}

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired return true if the specified file matched the build.zig.zon file name.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "build.zig.zon" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.stats == nil {
		return
	}
	e.stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts from build.zig.zon files
// It extract only name and version from the file if the mode is artifact, but if it is source code scanning mode, it will parse and extract dependencies field.
// Refer to example build.zig.zon file: https://github.com/ziglang/zig/blob/master/doc/build.zig.zon.md
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var pkgs []*extractor.Package
	var err error
	if e.scanDependencies {
		pkgs, err = e.parseDependenciesField(ctx, input)
	} else {
		pkgs, err = e.parseNameVersionInfo(ctx, input)
	}
	if e.stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inventory.Inventory{Packages: pkgs}, err
}

// nameEnumRe is a regexp for .name = .identifier (new format enum literal)
var nameEnumRe = regexp.MustCompile(`\.name\s*=\s*\.([A-Za-z_][A-Za-z0-9_]*)`)

// nameStrRe is a regexp for .name = "string" (old format quoted string)
var nameStrRe = regexp.MustCompile(`\.name\s*=\s*"([^"]*)"`)

// versionRe is a regexp for .version = "string"
var versionRe = regexp.MustCompile(`\.version\s*=\s*"([^"]*)"`)

// parseNameVersionInfo extracts top-level .name and .version both new and legacy version
//
// Supports:
//
//	.name = .zigmodule,   (new: enum literal)
//	.name = "zigmodule",   (old: quoted string)
//	.version = "0.0.1",
func (e Extractor) parseNameVersionInfo(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Package, error) {
	packages := []*extractor.Package{}
	content, err := io.ReadAll(input.Reader)
	contentStr := string(content)
	parsedPackageName := ""
	parsedVersionName := ""
	enumName := nameEnumRe.FindStringSubmatch(contentStr)
	stringName := nameStrRe.FindStringSubmatch(contentStr)
	versionName := versionRe.FindStringSubmatch(contentStr)
	if enumName != nil {
		parsedPackageName = enumName[1]
	} else if stringName != nil {
		parsedPackageName = stringName[1]
	}
	if versionName != nil {
		parsedVersionName = versionName[1]
	}

	if err != nil {
		return nil, fmt.Errorf("could not extract: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
	}
	if parsedPackageName != "" && parsedVersionName != "" {
		pkg := &extractor.Package{
			Name:      parsedPackageName,
			Version:   parsedVersionName,
			PURLType:  purl.TypeZig,
			Locations: []string{input.Path},
		}
		packages = append(packages, pkg)
	}

	return packages, err
}

// depsStartRe is a regexp for .dependencies = {...} block
var depsStartRe = regexp.MustCompile(`\.dependencies\s*=\s*\.?\{`)

// depKeyRe is a regexp for .dependencies list key ex:  .zul = .{ ... }
var depKeyRe = regexp.MustCompile(`\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\.?\{`)

// Dependency holds a single dependency entry
type Dependency struct {
	Name    string // extracted from .hash (or same as Key if legacy/path-only)
	Version string // extracted from .hash, empty for legacy "1220..." or path deps
}

// parseDependenciesField parses .dependencies list and extracts .name and .versions from this array
//
// Example Format:
//
//	 .dependencies = .{
//	       .zigrc = .{
//	           .url = "git+https://github.com/Aandreba/zigrc/#b1e98f1cc506e975bdb27341c27d920021e7b4d8",
//	           .hash = "zigrc-1.0.0-lENlWzvQAACulrbkL9PVhWjFsWSkYhi7AmfSbCM-2Xlh",
//	       },
//	},
func (e Extractor) parseDependenciesField(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Package, error) {
	packages := []*extractor.Package{}
	content, err := io.ReadAll(input.Reader)
	contentStr := string(content)

	if err != nil {
		return nil, fmt.Errorf("could not extract: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
	}
	depsBlock, err := e.extractDepBlock(contentStr)
	if err != nil {
		return nil, err
	}
	depsList := e.parseDependencyList(depsBlock)
	for _, d := range depsList {
		if d.Name != "" && d.Version != "" {
			pkg := &extractor.Package{
				Name:      d.Name,
				Version:   d.Version,
				PURLType:  purl.TypeZig,
				Locations: []string{input.Path},
			}
			packages = append(packages, pkg)
		}
	}

	return packages, nil
}

func (e Extractor) extractDepBlock(contentStr string) (string, error) {
	depsBlock := ""
	depsLoc := depsStartRe.FindStringIndex(contentStr)

	if depsLoc == nil {
		return "", errors.New("could not find .deps")
	}
	// Find the opening brace
	start := strings.Index(contentStr[depsLoc[0]:], "{") + depsLoc[0]
	depth := 0
	for i := start; i < len(contentStr); i++ {
		switch contentStr[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				depsBlock = contentStr[start+1 : i]
				return depsBlock, nil
			}
		}
	}
	if depsBlock == "" {
		return "", errors.New("could not find .deps")
	}
	return depsBlock, nil
}

func (e Extractor) parseDependencyList(dependencyBlock string) []Dependency {
	deps := []Dependency{}
	pos := 0
	for pos < len(dependencyBlock) {
		loc := depKeyRe.FindStringIndex(dependencyBlock[pos:])
		if loc == nil {
			break
		}

		absStart := pos + loc[0]
		absBodyStart := pos + loc[1] - 1 // position of '{'

		// Find matching closing brace
		depth := 0
		bodyEnd := absBodyStart
		for i := absBodyStart; i < len(dependencyBlock); i++ {
			switch dependencyBlock[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					bodyEnd = i
					goto foundEnd
				}
			}
		}
	foundEnd:
		entryContent := dependencyBlock[absBodyStart+1 : bodyEnd]

		dep := e.parseSingleDep(entryContent)
		deps = append(deps, dep)

		pos = absStart + 1
		// Advance past this whole entry to avoid re-matching nested keys
		if bodyEnd > pos {
			pos = bodyEnd + 1
		}
	}
	return deps
}

// hashRe is a regexp for .hash = "...",
var hashRe = regexp.MustCompile(`\.hash\s*=\s*"([^"]*)"`)

// sizedHashLen is for new hash format length: always exactly 44 chars at the end for .hash part
const sizedHashLen = 44

// parseSingleDep extracts name+version from a .hash value
//
// Formats for .hash:
//
//	Legacy:  "1220<hex>"                              -> no name/version
//	No-zon:  "N-V-<44chars>"                          -> name="N", version="V" (placeholder)
//	New:     "name-version-<44chars>"                 -> name, version (may contain dashes like "0.5.0-dev")
func (e Extractor) parseSingleDep(entryContent string) Dependency {
	dep := Dependency{}

	if m := hashRe.FindStringSubmatch(entryContent); m != nil {
		hashPart := m[1]
		// Legacy multihash format
		if strings.HasPrefix(hashPart, "1220") {
			dep.Name = ""
			dep.Version = ""
			return dep
		}

		if len(hashPart) <= sizedHashLen+1 {
			dep.Name = ""
			dep.Version = ""
			return dep
		}

		// Verify the character before the last 44 chars is a dash
		cutpoint := len(hashPart) - sizedHashLen
		if hashPart[cutpoint-1] != '-' {
			dep.Name = ""
			dep.Version = ""
			return dep
		}

		nameVersion := hashPart[:cutpoint-1] // e.g. "wayland-0.5.0-dev" or "zbor-0.18.0" or "N-V"

		// Name cannot contain dashes (Zig identifier rule: [A-Za-z_][A-Za-z0-9_]*) ref: https://github.com/ziglang/zig/issues/20178
		// so the first dash always separates name from version
		name, version, found := strings.Cut(nameVersion, "-")
		if !found {
			// No dash at all — name only, no version, still not valid for us
			dep.Name = nameVersion
			dep.Version = ""
			return dep
		}

		dep.Name = name
		dep.Version = version // everything after first dash is version

		// placeholder for packages which don't have build.zig.zon file
		if dep.Name == "N" && dep.Version == "V" {
			dep.Name = ""
			dep.Version = ""
		}
	}
	return dep
}
