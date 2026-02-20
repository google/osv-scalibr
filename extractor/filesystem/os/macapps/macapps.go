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

// Package macapps extracts applications data from Info.plist files of OS X devices.
package macapps

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/micromdm/plist"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/macapps"

	// noLimitMaxFileSizeBytes is a sentinel value that indicates no limit.
	noLimitMaxFileSizeBytes = int64(0)
)

// Extractor extracts Mac Apps from /Applications Directory.
type Extractor struct {
	Stats                  stats.Collector
	maxFileSizeBytes       int64
	allowCustomDirectories bool
}

// New returns a Mac App extractor.
//
// For most use cases, initialize with:
// ```
// e := New(&cpb.PluginConfig{}))
// ```
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxSize := noLimitMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxSize = cfg.GetMaxFileSizeBytes()
	}

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.MacAppsConfig { return c.GetMacapps() })
	if specific.GetMaxFileSizeBytes() > 0 {
		maxSize = specific.GetMaxFileSizeBytes()
	}

	return &Extractor{
		maxFileSizeBytes:       maxSize,
		allowCustomDirectories: specific.GetAllowCustomDirectories(),
	}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches the Info.plist file pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	// Check for the "/Applications" prefix if custom directories are not allowed.
	if !e.allowCustomDirectories && !strings.HasPrefix(path, "Applications/") {
		return false
	}

	if !strings.HasSuffix(path, "/Contents/Info.plist") {
		return false
	}

	// Skip sub packages.
	if strings.Count(path, "/Contents/") != 1 {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > noLimitMaxFileSizeBytes && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultOK)
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

// Extract extracts packages from Info.plist files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	p, err := e.extractFromInput(input)
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
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("macOS Application.extract: %w", err)
	}
	if p == nil {
		return inventory.Inventory{}, nil
	}
	return inventory.Inventory{Packages: []*extractor.Package{p}}, nil
}

func (e Extractor) extractFromInput(input *filesystem.ScanInput) (*extractor.Package, error) {
	// Read the first 8 bytes to check for binary plist header
	header := make([]byte, 8)
	_, err := io.ReadFull(input.Reader, header)
	if err != nil {
		return nil, fmt.Errorf("error reading plist header: %w", err)
	}
	// Type Cast to ReadSeeker
	rs, ok := input.Reader.(io.ReadSeeker)              // Type assertion
	if _, err := rs.Seek(0, io.SeekStart); err != nil { // Use seeker here
		return nil, fmt.Errorf("error seeking to beginning of file: %w", err)
	}
	var metadata Metadata

	if !ok {
		return nil, errors.New("input.Reader does not support readseeker")
	}
	if string(header) == "bplist00" {
		// Binary plist
		decoder := plist.NewBinaryDecoder(rs)
		err := decoder.Decode(&metadata)
		if err != nil {
			return nil, fmt.Errorf("error decoding Binary plist: %w", err)
		}
	} else {
		// XML plist
		decoder := plist.NewXMLDecoder(input.Reader)
		err := decoder.Decode(&metadata)
		if err != nil {
			return nil, fmt.Errorf("error decoding XML plist: %w", err)
		}
	}

	p := &extractor.Package{
		Name:      metadata.CFBundleName,
		Version:   metadata.CFBundleShortVersionString,
		PURLType:  purl.TypeMacApps,
		Metadata:  &metadata,
		Locations: []string{input.Path},
	}

	return p, nil
}
