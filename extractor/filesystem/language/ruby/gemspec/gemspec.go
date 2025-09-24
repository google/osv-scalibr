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

// Package gemspec extracts *.gemspec files.
package gemspec

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "ruby/gemspec"
)

// Regex expressions used for extracting gemspec package name and version.
var (
	reSpec            = regexp.MustCompile(`^Gem::Specification\.new`)
	reName            = regexp.MustCompile(`\s*\w+\.name\s*=\s*["']([^"']+)["']`)
	reVerLiteral      = regexp.MustCompile(`\s*\w+\.version\s*=\s*["']([^"']+)["']`)
	reVerConst        = regexp.MustCompile(`\s*\w+\.version\s*=\s*([A-Za-z0-9_:]+)`)
	reRequireRel      = regexp.MustCompile(`^\s*require_relative\s+["']([^"']+)["']`)
	reConstAssignment = regexp.MustCompile(`\b([A-Z][A-Za-z0-9_]*)\s*=\s*(?:'([^']+)'|"([^"]+)")(?:\s*\.freeze)?`)
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: 0,
	}
}

// Extractor extracts RubyGem package info from *.gemspec files.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Ruby gemspec extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:            cfg.Stats,
		maxFileSizeBytes: cfg.MaxFileSizeBytes,
	}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired return true if the specified file matched the .gemspec file
// pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Ext(path) != ".gemspec" {
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

// Extract extracts packages from the .gemspec file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	p, err := extract(input.Path, input.FS, input.Reader)
	e.reportFileExtracted(input.Path, input.Info, filesystem.ExtractorErrorToFileExtractedResult(err))
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("gemspec.parse: %w", err)
	}
	if p == nil {
		return inventory.Inventory{}, nil
	}

	p.Locations = []string{input.Path}
	return inventory.Inventory{Packages: []*extractor.Package{p}}, nil
}

func (e Extractor) reportFileExtracted(path string, fileinfo fs.FileInfo, result stats.FileExtractedResult) {
	if e.stats == nil {
		return
	}
	var fileSizeBytes int64
	if fileinfo != nil {
		fileSizeBytes = fileinfo.Size()
	}
	e.stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// extract searches for the required name and version lines in the gemspec
// file using regex. It handles version strings defined either inline or via a
// constant populated through require_relative.
// Based on: https://guides.rubygems.org/specification-reference/
func extract(path string, fsys fs.FS, r io.Reader) (*extractor.Package, error) {
	buf := bufio.NewScanner(r)
	gemName, gemVer := "", ""
	foundStart := false
	var (
		requirePaths    []string
		versionConst    string
		inlineConstants = make(map[string]string)
	)

	for buf.Scan() {
		line := buf.Text()

		if matches := reRequireRel.FindStringSubmatch(line); len(matches) > 1 {
			requirePaths = append(requirePaths, matches[1])
		}

		if matches := reConstAssignment.FindStringSubmatch(line); len(matches) > 1 {
			if val := constantValueFromMatch(matches); val != "" {
				inlineConstants[matches[1]] = val
			}
		}

		if !foundStart {
			start := reSpec.FindString(line)
			if start != "" {
				foundStart = true
			}
			continue
		}
		if gemName != "" && gemVer != "" {
			break
		}
		if gemName == "" {
			nameArr := reName.FindStringSubmatch(line)
			if len(nameArr) > 1 {
				gemName = nameArr[1]
				continue
			}
		}
		if gemVer == "" {
			if verArr := reVerLiteral.FindStringSubmatch(line); len(verArr) > 1 {
				gemVer = verArr[1]
				continue
			}
			if versionConst == "" {
				if constMatch := reVerConst.FindStringSubmatch(line); len(constMatch) > 1 {
					versionConst = constMatch[1]
				}
			}
		}
	}

	if err := buf.Err(); err != nil {
		log.Warnf("error scanning gemspec file %s: %v", path, err)
	}

	// This was likely a marshalled gemspec. Not a readable text file.
	if !foundStart {
		log.Warnf("error scanning gemspec (%s) could not find start of spec definition", path)
		return nil, nil
	}

	if gemVer == "" && versionConst != "" {
		if constName, ok := versionConstantName(versionConst); ok {
			if v, ok := inlineConstants[constName]; ok {
				gemVer = v
			} else if resolved, err := resolveVersionFromRequires(fsys, path, requirePaths, constName); err == nil {
				gemVer = resolved
			} else {
				log.Debugf("unable to resolve version constant %q in gemspec %s: %v", versionConst, path, err)
			}
		}
	}

	if gemName == "" || gemVer == "" {
		return nil, fmt.Errorf("failed to parse gemspec name (%v) and version (%v)", gemName, gemVer)
	}

	return &extractor.Package{
		Name:     gemName,
		Version:  gemVer,
		PURLType: purl.TypeGem,
	}, nil
}

func resolveVersionFromRequires(fsys fs.FS, gemspecPath string, requirePaths []string, constName string) (string, error) {
	if fsys == nil {
		return "", fmt.Errorf("filesystem unavailable for resolving version constant")
	}

	gemspecDir := filepath.Dir(gemspecPath)
	visited := make(map[string]struct{})

	for _, req := range requirePaths {
		if req == "" {
			continue
		}

		candidates := versionFileCandidates(req)
		for _, candidate := range candidates {
			fullPath := candidate
			if gemspecDir != "." && gemspecDir != "" {
				fullPath = filepath.Join(gemspecDir, candidate)
			}
			fullPath = filepath.Clean(fullPath)
			if _, ok := visited[fullPath]; ok {
				continue
			}
			visited[fullPath] = struct{}{}

			version, err := findConstantValueInFile(fsys, fullPath, constName)
			if err == nil {
				return version, nil
			}
		}
	}

	return "", fmt.Errorf("unable to resolve constant %s from require_relative targets", constName)
}

func versionConstantName(expr string) (string, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", false
	}
	parts := strings.Split(expr, "::")
	name := parts[len(parts)-1]
	if name != "VERSION" {
		return "", false
	}
	return name, true
}

func versionFileCandidates(req string) []string {
	req = strings.TrimSpace(req)
	req = strings.TrimPrefix(req, "./")
	req = filepath.Clean(req)
	if filepath.Ext(req) == ".rb" {
		return []string{req}
	}
	return []string{req, req + ".rb"}
}

func constantValueFromMatch(matches []string) string {
	if len(matches) > 2 && matches[2] != "" {
		return matches[2]
	}
	if len(matches) > 3 && matches[3] != "" {
		return matches[3]
	}
	return ""
}

func findConstantValueInFile(fsys fs.FS, path, constName string) (string, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if matches := reConstAssignment.FindStringSubmatch(line); len(matches) > 1 && matches[1] == constName {
			if val := constantValueFromMatch(matches); val != "" {
				return val, nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("constant %s not found in %s", constName, path)
}
