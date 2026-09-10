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

// Package gem extracts packages from Ruby .gem archives.
package gem

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"

	"archive/tar"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"gopkg.in/yaml.v3"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "ruby/gem"

	// defaultMaxFileSizeBytes is the default maximum file size the extractor will
	// attempt to extract. If a file is encountered that is larger than this
	// limit, the file is ignored by `FileRequired`.
	defaultMaxFileSizeBytes = 20 * units.MiB
)

// Extractor extracts Ruby packages from .gem archives.
type Extractor struct {
	Stats               stats.Collector
	maxFileSizeBytes    int64
	includeDependencies bool
}

// New returns a Ruby gem extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	includeDependencies := false
	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.RubyGemConfig {
		return c.GetRubyGem()
	})
	if specific != nil {
		if specific.GetMaxFileSizeBytes() > 0 {
			maxFileSizeBytes = specific.GetMaxFileSizeBytes()
		}
		includeDependencies = specific.GetIncludeDependencies()
	}

	return &Extractor{
		maxFileSizeBytes:    maxFileSizeBytes,
		includeDependencies: includeDependencies,
	}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches .gem.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	filePath := api.Path()
	if path.Ext(filePath) != ".gem" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if fileinfo.IsDir() {
		return false
	}
	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(filePath, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(filePath, fileinfo.Size(), stats.FileRequiredResultOK)
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

// Extract extracts packages from the .gem file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := e.extractPackages(input.Path, input.Reader)
	e.reportFileExtracted(input.Path, input.Info, err)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("gem.Extract: %w", err)
	}

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

func (e Extractor) extractPackages(archivePath string, r io.Reader) ([]*extractor.Package, error) {
	tr := tar.NewReader(r)
	var metaGzReader io.Reader
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading gem tar archive %s: %w", archivePath, err)
		}
		cleanName := path.Clean(hdr.Name)
		if cleanName == "metadata.gz" && hdr.Typeflag == tar.TypeReg {
			metaGzReader = tr
			break
		}
	}
	if metaGzReader == nil {
		return nil, fmt.Errorf("metadata.gz not found in gem archive %s", archivePath)
	}

	gz, err := gzip.NewReader(metaGzReader)
	if err != nil {
		return nil, fmt.Errorf("opening gzip reader for %s: %w", archivePath, err)
	}
	defer gz.Close()

	limit := 5 * units.MiB
	content, err := io.ReadAll(io.LimitReader(gz, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading decompressed metadata from %s: %w", archivePath, err)
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("decompressed metadata in %s exceeds size limit of %d bytes", archivePath, limit)
	}

	var spec gemSpecification
	if err := yaml.Unmarshal(content, &spec); err != nil {
		return nil, fmt.Errorf("parsing gem specification yaml in %s: %w", archivePath, err)
	}

	if spec.Name == "" || string(spec.Version) == "" {
		log.Debugf("gem specification in %s does not have a valid name and/or version", archivePath)
		return nil, nil
	}

	rootLoc := extractor.LocationFromPath(archivePath)
	rootPkg := &extractor.Package{
		Name:     spec.Name,
		Version:  string(spec.Version),
		PURLType: purl.TypeGem,
		Location: rootLoc,
		Metadata: &RubyGemMetadata{
			Authors:      spec.Authors,
			Description:  spec.Description,
			Homepage:     spec.Homepage,
			Licenses:     spec.Licenses,
			Dependencies: spec.Dependencies,
			Platform:     spec.Platform,
			Summary:      spec.Summary,
		},
	}

	pkgs := []*extractor.Package{rootPkg}

	if e.includeDependencies {
		for _, dep := range spec.Dependencies {
			if !dep.IsRuntime() {
				continue
			}
			resolvedVer, ok := ResolveDependencyVersion(dep.Requirements())
			if !ok {
				continue
			}
			pkgs = append(pkgs, &extractor.Package{
				Name:     dep.Name,
				Version:  resolvedVer,
				PURLType: purl.TypeGem,
				Location: rootLoc,
			})
		}
	}

	return pkgs, nil
}
