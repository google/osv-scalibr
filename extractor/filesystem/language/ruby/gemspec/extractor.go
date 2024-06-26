// Copyright 2024 Google LLC
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

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

// Regex expressions used for extracting gemspec package name and version.
var (
	reSpec = regexp.MustCompile(`^Gem::Specification\.new`)
	reName = regexp.MustCompile(`\s*\w+\.name\s*=\s*["']([^"']+)["']`)
	reVer  = regexp.MustCompile(`\s*\w+\.version\s*=\s*["']([^"']+)["']`)
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

// Name of the extractor
func (e Extractor) Name() string { return "ruby/gemspec" }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// FileRequired return true if the specified file matched the .gemspec file
// pattern.
func (e Extractor) FileRequired(path string, fileinfo fs.FileInfo) bool {
	if filepath.Ext(path) != ".gemspec" {
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
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	i, err := extract(input.Path, input.Reader)
	e.reportFileExtracted(input.Path, input.Info, filesystem.ExtractorErrorToFileExtractedResult(err))
	if err != nil {
		return nil, fmt.Errorf("gemspec.parse(%s): %w", input.Path, err)
	}
	if i == nil {
		return []*extractor.Inventory{}, nil
	}

	i.Locations = []string{input.Path}
	return []*extractor.Inventory{i}, nil
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
// file using regex.
// Based on: https://guides.rubygems.org/specification-reference/
func extract(path string, r io.Reader) (*extractor.Inventory, error) {
	buf := bufio.NewScanner(r)
	gemName, gemVer := "", ""
	foundStart := false

	for buf.Scan() {
		line := buf.Text()

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
			verArr := reVer.FindStringSubmatch(line)
			if len(verArr) > 1 {
				gemVer = verArr[1]
				continue
			}
		}
	}

	if err := buf.Err(); err != nil {
		log.Warnf("error scanning gemspec file %s: %w", path, err)
	}

	// This was likely a marshalled gemspec. Not a readable text file.
	if !foundStart {
		log.Warnf("error scanning gemspec (%s) could not find start of spec definition", path)
		return nil, nil
	}

	if gemName == "" || gemVer == "" {
		return nil, fmt.Errorf("failed to parse gemspec name (%v) and version (%v)", gemName, gemVer)
	}

	return &extractor.Inventory{
		Name:    gemName,
		Version: gemVer,
	}, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return &purl.PackageURL{
		Type:    purl.TypeGem,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }
