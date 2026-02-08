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

// Package snap extracts snap packages
package snap

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	snapmeta "github.com/google/osv-scalibr/extractor/filesystem/os/snap/metadata"
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
	Name = "os/snap"

	// noLimitMaxFileSizeBytes is a sentinel value that indicates no limit.
	noLimitMaxFileSizeBytes = int64(0)
)

type snap struct {
	Name          string   `yaml:"name"`
	Version       string   `yaml:"version"`
	Grade         string   `yaml:"grade"`
	Type          string   `yaml:"type"`
	Architectures []string `yaml:"architectures"`
}

// Extractor extracts snap apps.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a SNAP extractor.
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

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.SnapConfig { return c.GetSnap() })
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
	return &plugin.Capabilities{OS: plugin.OSLinux}
}

// the yaml file is found in snap/<app>/<revision>/meta/snap.yaml
var filePathRegex = regexp.MustCompile(`^snap/[^/]*/[^/]*/meta/snap.yaml$`)

// FileRequired returns true if the specified file matches snap.yaml file pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if !strings.HasSuffix(path, "snap.yaml") {
		return false
	}

	if match := filePathRegex.FindString(path); match == "" {
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

// Extract extracts snap info from snap.yaml file passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := e.extractFromInput(input)
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
	return inventory.Inventory{Packages: pkgs}, err
}

func (e Extractor) extractFromInput(input *filesystem.ScanInput) ([]*extractor.Package, error) {
	m, err := osrelease.GetOSRelease(input.FS)
	if err != nil {
		log.Errorf("osrelease.ParseOsRelease(): %v", err)
	}

	snap := snap{}
	dec := yaml.NewDecoder(input.Reader)
	if err := dec.Decode(&snap); err != nil {
		return nil, fmt.Errorf("failed to yaml decode: %w", err)
	}

	if snap.Name == "" {
		return nil, errors.New("missing snap name")
	}

	if snap.Version == "" {
		return nil, errors.New("missing snap version")
	}

	pkg := &extractor.Package{
		Name:     snap.Name,
		Version:  snap.Version,
		PURLType: purl.TypeSnap,
		Metadata: &snapmeta.Metadata{
			Name:              snap.Name,
			Version:           snap.Version,
			Grade:             snap.Grade,
			Type:              snap.Type,
			Architectures:     snap.Architectures,
			OSID:              m["ID"],
			OSVersionCodename: m["VERSION_CODENAME"],
			OSVersionID:       m["VERSION_ID"],
		},
		Locations: []string{input.Path},
	}
	return []*extractor.Package{pkg}, nil
}
