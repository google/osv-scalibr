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

// Package wheelegg extracts wheel and egg files.
package wheelegg

import (
	"archive/zip"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/internal/pypipurl"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/wheelegg"

	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 100 * units.MiB
)

// Extractor extracts python packages from wheel/egg files.
type Extractor struct {
	maxFileSizeBytes int64
	stats            stats.Collector
}

// Config is the configuration for the Extractor.
type Config struct {
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
}

// DefaultConfig returns the default configuration for the wheel/egg extractor.
func DefaultConfig() Config {
	return Config{
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
		Stats:            nil,
	}
}

// New returns a wheel/egg extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		maxFileSizeBytes: cfg.MaxFileSizeBytes,
		stats:            cfg.Stats,
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

var (
	requiredFiles = []string{
		// Metadata format
		"EGG-INFO/PKG-INFO",
		".egg-info",
		".egg-info/PKG-INFO",
		".dist-info/METADATA",
		// zip file with Metadata files inside.
		".egg",
	}
)

// FileRequired returns true if the specified file matches python Metadata file
// patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	// For Windows
	normalizedPath := filepath.ToSlash(path)

	for _, r := range requiredFiles {
		if strings.HasSuffix(normalizedPath, r) {
			fileinfo, err := api.Stat()
			if err != nil {
				return false
			}

			// We only want to skip the file for being too large if it is a relevant
			// file at all, so we check the file size after checking the file suffix.
			if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
				e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
				return false
			}

			e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultOK)
			return true
		}
	}
	return false
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

// Extract extracts packages from wheel/egg files passed through the scan input.
// For .egg files, input.Info.Size() is required to unzip the file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory []*extractor.Inventory, err error) {
	if strings.HasSuffix(input.Path, ".egg") {
		// TODO(b/280417821): In case extractZip returns no inventory, we could parse the filename.
		inventory, err = e.extractZip(ctx, input)
	} else {
		var i *extractor.Inventory
		if i, err = e.extractSingleFile(input.Reader, input.Path); i != nil {
			inventory = []*extractor.Inventory{i}
		}
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
	return inventory, err
}

// ErrSizeNotSet will trigger when Info.Size() is not set.
var ErrSizeNotSet = errors.New("input.Info is nil, but should have Size set")

func (e Extractor) extractZip(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	r, err := scalibrfs.NewReaderAt(input.Reader)
	if err != nil {
		return nil, fmt.Errorf("newReaderAt(%s): %w", input.Path, err)
	}

	if input.Info == nil {
		return nil, ErrSizeNotSet
	}
	s := input.Info.Size()
	zr, err := zip.NewReader(r, s)
	if err != nil {
		return nil, fmt.Errorf("zip.NewReader(%s): %w", input.Path, err)
	}
	inventory := []*extractor.Inventory{}
	for _, f := range zr.File {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if !e.FileRequired(simplefileapi.New(f.Name, f.FileInfo())) {
			continue
		}
		i, err := e.openAndExtract(f, input)
		if err != nil {
			return inventory, err
		}
		inventory = append(inventory, i)
	}
	return inventory, nil
}

func (e Extractor) openAndExtract(f *zip.File, input *filesystem.ScanInput) (*extractor.Inventory, error) {
	r, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("on %q: Open(%s): %w", input.Path, f.Name, err)
	}
	defer r.Close()

	// TODO(b/280438976): Store the path inside the zip file.
	i, err := e.extractSingleFile(r, input.Path)
	if err != nil {
		return nil, err
	}

	return i, nil
}

func (e Extractor) extractSingleFile(r io.Reader, path string) (*extractor.Inventory, error) {
	i, err := parse(r)
	if err != nil {
		return nil, fmt.Errorf("wheelegg.parse(%s): %w", path, err)
	}

	i.Locations = []string{path}
	return i, nil
}

func parse(r io.Reader) (*extractor.Inventory, error) {
	rd := textproto.NewReader(bufio.NewReader(r))
	h, err := rd.ReadMIMEHeader()
	name := h.Get("Name")
	version := h.Get("version")
	if name == "" || version == "" {
		// In case we got name and version but also an error, we ignore the error. This can happen in
		// malformed files like passlib 1.7.4.
		if err != nil {
			return nil, fmt.Errorf("ReadMIMEHeader(): %w %s %s", err, h.Get("Name"), h.Get("version"))
		}
		return nil, fmt.Errorf("Name or version is empty (name: %q, version: %q)", name, version)
	}

	return &extractor.Inventory{
		Name:    name,
		Version: version,
		Metadata: &PythonPackageMetadata{
			Author:      h.Get("Author"),
			AuthorEmail: h.Get("Author-email"),
		},
	}, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return pypipurl.MakePackageURL(i)
}

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
func (Extractor) Ecosystem(_ *extractor.Inventory) string { return "PyPI" }
