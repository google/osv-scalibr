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

// Package module extracts .ko files from kernel modules.
package module

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	modulemeta "github.com/google/osv-scalibr/extractor/filesystem/os/kernel/module/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/kernel/module"

	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 100 * units.MiB
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the kernel module extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor extracts packages from kernel module files (.ko).
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a kernel module extractor.
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:            cfg.Stats,
		maxFileSizeBytes: cfg.MaxFileSizeBytes,
	}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// Config returns the configuration of the extractor.
func (e Extractor) Config() Config {
	return Config{
		Stats:            e.stats,
		MaxFileSizeBytes: e.maxFileSizeBytes,
	}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches the *.ko file patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()

	if !strings.HasSuffix(filepath.Base(path), ".ko") {
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

// Extract extracts packages from .ko files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := e.extractFromInput(input)

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

func (e Extractor) extractFromInput(input *filesystem.ScanInput) ([]*extractor.Package, error) {
	packages := []*extractor.Package{}

	m, err := osrelease.GetOSRelease(input.FS)
	if err != nil {
		log.Errorf("osrelease.ParseOsRelease(): %v", err)
	}

	var readerAt io.ReaderAt
	if fileWithReaderAt, ok := input.Reader.(io.ReaderAt); ok {
		readerAt = fileWithReaderAt
	} else {
		buf := bytes.NewBuffer([]byte{})
		_, err := io.Copy(buf, input.Reader)
		if err != nil {
			return []*extractor.Package{}, err
		}
		readerAt = bytes.NewReader(buf.Bytes())
	}
	elfFile, err := elf.NewFile(readerAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ELF file: %w", err)
	}

	// Note that it's possible to strip section names from the binary so we might not be able
	// to identify malicious modules if the author intentionally stripped the module name.
	section := elfFile.Section(".modinfo")
	if section == nil {
		return nil, errors.New("no .modinfo section found")
	}

	sectionData, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read .modinfo section: %w", err)
	}

	var metadata modulemeta.Metadata

	// Sections are delimited by null bytes (\x00)
	for _, line := range bytes.Split(sectionData, []byte{'\x00'}) {
		if len(line) == 0 {
			continue
		}

		entry := strings.SplitN(string(line), "=", 2)
		if len(entry) != 2 {
			return nil, fmt.Errorf("malformed .modinfo entry, expected 'key=value' but got: %s", string(line))
		}

		key := entry[0]
		value := entry[1]

		switch key {
		case "name":
			metadata.PackageName = value
		case "version":
			metadata.PackageVersion = value
		case "srcversion":
			metadata.PackageSourceVersionIdentifier = value
		case "vermagic":
			metadata.PackageVermagic = strings.TrimSpace(value)
		case "author":
			metadata.PackageAuthor = value
		}
	}

	metadata.OSID = m["ID"]
	metadata.OSVersionCodename = m["VERSION_CODENAME"]
	metadata.OSVersionID = m["VERSION_ID"]

	p := &extractor.Package{
		Name:      metadata.PackageName,
		Version:   metadata.PackageVersion,
		Metadata:  &metadata,
		Locations: []string{input.Path},
	}

	packages = append(packages, p)

	return packages, nil
}
