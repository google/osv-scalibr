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

// Package rpmfile extract metadata from .rpm package files.
package rpmfile

import (
	"context"
	"fmt"
	"strings"

	"github.com/cavaliergopher/rpm"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	rpmmeta "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the name for the RPMFILE extractor
	Name = "os/rpmfile"
	// noLimitMaxFileSizeBytes is a sentinel value that indicates no limit.
	noLimitMaxFileSizeBytes = int64(0)
)

// Extractor extracts rpm packages from rpm database.
type Extractor struct {
	maxFileSizeBytes int64
}

// New returns an RPMFILE extractor.
//
// For most use cases, initialize with:
// ```
// e := New(&cpb.PluginConfig{})
// ```
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := noLimitMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.RpmFileConfig { return c.GetRpmfile() })
	if specific.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = specific.GetMaxFileSizeBytes()
	}
	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file is an rpm package file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()

	if !strings.HasSuffix(path, ".rpm") {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > noLimitMaxFileSizeBytes && fileinfo.Size() > e.maxFileSizeBytes {
		return false
	}
	return true
}

// Extract extracts packages from rpm package files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	rpmPkg, err := rpm.Read(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("RPM file parsing failed (%s): %w", input.Path, err)
	}

	var pkg *extractor.Package
	metadata := &rpmmeta.Metadata{
		PackageName:  rpmPkg.Name(),
		SourceRPM:    rpmPkg.SourceRPM(),
		Epoch:        rpmPkg.Epoch(),
		Vendor:       rpmPkg.Vendor(),
		Architecture: rpmPkg.Architecture(),
	}

	pkg = &extractor.Package{
		Name:     rpmPkg.Name(),
		Version:  fmt.Sprintf("%s-%s", rpmPkg.Version(), rpmPkg.Release()),
		PURLType: purl.TypeRPM,
		Location: extractor.LocationFromPath(input.Path),
		Metadata: metadata,
		Licenses: []string{rpmPkg.License()},
	}
	return inventory.Inventory{Packages: []*extractor.Package{pkg}}, err
}
