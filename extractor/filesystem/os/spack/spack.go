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

// Package spack extracts packages from spack spec.json files.
package spack

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	spackmeta "github.com/google/osv-scalibr/extractor/filesystem/os/spack/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/spack"

	// noLimitMaxFileSizeBytes is a sentinel value that indicates no limit.
	noLimitMaxFileSizeBytes = int64(0)
)

// specJSON represents the top-level structure of a spack spec.json file.
type specJSON struct {
	Spec struct {
		Nodes []node `json:"nodes"`
	} `json:"spec"`
}

// arch represents the architecture information of a spack node.
type arch struct {
	Platform   string          `json:"platform"`
	PlatformOS string          `json:"platform_os"`
	Target     json.RawMessage `json:"target"`
}

// node represents a single package node in the spack spec.
type node struct {
	Name     string           `json:"name"`
	Version  string           `json:"version"`
	Arch     *arch            `json:"arch,omitempty"`
	Hash     string           `json:"hash"`
	External *json.RawMessage `json:"external,omitempty"`
}

// targetName extracts the architecture target name from the arch field.
// The target can be either a plain string (e.g., "x86_64") or an object
// with a "name" field (e.g., {"name": "skylake", ...}).
func (a *arch) targetName() string {
	if a == nil || len(a.Target) == 0 {
		return ""
	}

	// Try as a plain string first.
	var s string
	if err := json.Unmarshal(a.Target, &s); err == nil {
		return s
	}

	// Try as an object with a "name" field.
	var obj struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(a.Target, &obj); err == nil {
		return obj.Name
	}

	return ""
}

// Extractor extracts Spack packages from .spack/spec.json files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Spack extractor.
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

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.SpackConfig { return c.GetSpecjson() })
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
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches the .spack/spec.json pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if !strings.HasSuffix(path, ".spack/spec.json") {
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

// Extract extracts packages from spack spec.json files passed through the scan input.
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
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("spack.extract: %w", err)
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

func (e Extractor) extractFromInput(input *filesystem.ScanInput) ([]*extractor.Package, error) {
	var spec specJSON
	err := json.NewDecoder(input.Reader).Decode(&spec)
	if err != nil {
		return nil, fmt.Errorf("failed to json decode: %w", err)
	}

	var pkgs []*extractor.Package
	for _, n := range spec.Spec.Nodes {
		// Skip nodes with an "external" field.
		if n.External != nil {
			continue
		}

		if n.Name == "" || n.Version == "" {
			continue
		}

		m := &spackmeta.Metadata{
			PackageName:    n.Name,
			PackageVersion: n.Version,
			Hash:           n.Hash,
		}

		if n.Arch != nil {
			m.Platform = n.Arch.Platform
			m.PlatformOS = n.Arch.PlatformOS
			m.Architecture = n.Arch.targetName()
		}

		p := &extractor.Package{
			Name:      n.Name,
			Version:   n.Version,
			PURLType:  purl.TypeSpack,
			Metadata:  m,
			Locations: []string{input.Path},
		}
		pkgs = append(pkgs, p)
	}

	return pkgs, nil
}
