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

// Package dockerfile extracts container image references from Dockerfile FROM directives.
package dockerfile

import (
	"bufio"
	"context"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
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
	Name = "containers/dockerfile"

	// defaultMaxFileSizeBytes is the default maximum file size the extractor will
	// attempt to extract. If a file is encountered that is larger than this
	// limit, the file is ignored by FileRequired.
	defaultMaxFileSizeBytes = 1 * units.MiB
)

// Extractor extracts container image references from Dockerfile FROM directives.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Dockerfile image extractor.
//
// For most use cases, initialize with:
// ```
// e := New(&cpb.PluginConfig{})
// ```
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSize := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSize = cfg.GetMaxFileSizeBytes()
	}

	return &Extractor{maxFileSizeBytes: maxFileSize}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is a Dockerfile.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	filename := strings.ToLower(filepath.Base(path))
	if filename != "dockerfile" && !strings.HasPrefix(filename, "dockerfile.") && !strings.HasSuffix(filename, ".dockerfile") {
		return false
	}

	fi, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > 0 && fi.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fi.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fi.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts container image references from a Dockerfile.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input.Info == nil {
		return inventory.Inventory{}, errors.New("input.Info is nil")
	}
	if input.Info.Size() > e.maxFileSizeBytes {
		log.Infof("Skipping too large file: %s", input.Path)
		return inventory.Inventory{}, nil
	}

	pkgs, err := parse(input.Reader, input.Path)
	if err != nil {
		log.Debugf("dockerfile: parse failed for %s: %v", input.Path, err)
		return inventory.Inventory{}, nil
	}

	e.reportFileExtracted(input.Path, input.Info, nil)
	return inventory.Inventory{Packages: pkgs}, nil
}

func (e Extractor) reportFileExtracted(path string, fileinfo fs.FileInfo, err error) {
	if e.Stats == nil {
		return
	}
	var fileSizeBytes int64
	if fileinfo != nil {
		fileSizeBytes = fileinfo.Size()
	}
	e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
		Path:          path,
		Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
		FileSizeBytes: fileSizeBytes,
	})
}

func parse(r io.Reader, path string) ([]*extractor.Package, error) {
	scanner := bufio.NewScanner(r)
	seen := make(map[string]struct{})
	var pkgs []*extractor.Package

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.EqualFold(fields[0], "FROM") {
			continue
		}

		// Skip flags like --platform=..., --pull=... before the image name.
		imageRef := ""
		for i := 1; i < len(fields); i++ {
			if strings.HasPrefix(fields[i], "--") {
				continue
			}
			imageRef = fields[i]
			break
		}
		if imageRef == "" {
			continue
		}

		// Skip unresolved variable references (e.g. $BASE_IMAGE, ${VAR}).
		if strings.Contains(imageRef, "$") {
			continue
		}

		if _, ok := seen[imageRef]; ok {
			continue
		}
		seen[imageRef] = struct{}{}

		name, version := parseName(imageRef)
		pkgs = append(pkgs, &extractor.Package{
			Location: extractor.LocationFromPath(path),
			Name:     name,
			Version:  version,
			PURLType: purl.TypeDocker,
		})
	}

	return pkgs, scanner.Err()
}

// parseName parses a container image name to extract the name and version/tag/digest.
// It handles both digest format (name@digest) and tag format (name:tag).
// If no version is specified, it returns "latest" as the default version.
func parseName(name string) (string, string) {
	if strings.Contains(name, "@") {
		parts := strings.SplitN(name, "@", 2)
		return parts[0], parts[1]
	}
	if lastColon := strings.LastIndex(name, ":"); lastColon != -1 {
		return name[:lastColon], name[lastColon+1:]
	}
	return name, "latest"
}

var _ filesystem.Extractor = Extractor{}
