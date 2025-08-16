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

// Package vmlinuz extracts information about vmlinuz compressed kernel images.
package vmlinuz

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/deitch/magic/pkg/magic"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	vmlinuzmeta "github.com/google/osv-scalibr/extractor/filesystem/os/kernel/vmlinuz/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/kernel/vmlinuz"

	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 30 * units.MiB
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the kernel vmlinuz extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor extracts information from kernel vmlinuz files (vmlinuz).
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a kernel vmlinuz extractor.
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

// FileRequired returns true if the specified file matches the vmlinuz file patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()

	if !strings.HasPrefix(path, "boot/") {
		return false
	}

	if !(filepath.Base(path) == "vmlinuz" || strings.HasPrefix(filepath.Base(path), "vmlinuz-")) {
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

// Extract extracts information from vmlinuz files passed through the scan input.
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

	r, err := scalibrfs.NewReaderAt(input.Reader)
	if err != nil {
		return nil, fmt.Errorf("NewReaderAt: %w", err)
	}

	magicType, err := magic.GetType(r)
	if err != nil {
		return nil, fmt.Errorf("error determining magic type: %w", err)
	}

	if len(magicType) == 0 || magicType[0] != "Linux kernel" {
		return nil, errors.New("no match with linux kernel found")
	}

	metadata := parseVmlinuzMetadata(magicType)

	metadata.OSID = m["ID"]
	metadata.OSVersionCodename = m["VERSION_CODENAME"]
	metadata.OSVersionID = m["VERSION_ID"]

	p := &extractor.Package{
		Name:      metadata.Name,
		Version:   metadata.Version,
		Metadata:  &metadata,
		Locations: []string{input.Path},
	}

	packages = append(packages, p)

	return packages, nil
}

func parseVmlinuzMetadata(magicType []string) vmlinuzmeta.Metadata {
	var m vmlinuzmeta.Metadata

	m.Name = "Linux Kernel"

	for _, t := range magicType {
		switch {
		// Architecture
		case strings.HasPrefix(t, "x86 "):
			m.Architecture = "x86"
		case strings.HasPrefix(t, "ARM64 "):
			m.Architecture = "arm64"
		case strings.HasPrefix(t, "ARM "):
			m.Architecture = "arm"

		// Format
		case t == "bzImage":
			m.Format = "bzImage"
		case t == "zImage":
			m.Format = "zImage"

		// Version and extended version
		case strings.HasPrefix(t, "version "):
			m.ExtendedVersion = strings.TrimPrefix(t, "version ")
			if fields := strings.Fields(m.ExtendedVersion); len(fields) > 0 {
				m.Version = fields[0]
			}

		// RW-rootFS
		case strings.Contains(t, "rootFS") && strings.HasPrefix(t, "RW-"):
			m.RWRootFS = true

		// Swap device
		case strings.HasPrefix(t, "swap_dev "):
			swapHex := strings.TrimPrefix(t, "swap_dev 0X")
			swapConv, err := strconv.ParseInt(swapHex, 16, 32)
			if err != nil {
				log.Errorf("Failed to parse swap device: %v", err)
				continue
			}
			m.SwapDevice = int32(swapConv)

		// Root device
		case strings.HasPrefix(t, "root_dev "):
			rootHex := strings.TrimPrefix(t, "swap_dev 0X")
			rootConv, err := strconv.ParseInt(rootHex, 16, 32)
			if err != nil {
				log.Errorf("Failed to parse swap device: %v", err)
				continue
			}
			m.RootDevice = int32(rootConv)

		// Video mode
		case strings.Contains(t, "VGA") || strings.Contains(t, "Video"):
			m.VideoMode = t
		}
	}
	return m
}
