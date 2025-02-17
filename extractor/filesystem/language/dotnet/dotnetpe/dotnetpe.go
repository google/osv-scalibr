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

// Package dotnetpe extracts packages from .NET PE files.
package dotnetpe

import (
	"context"
	"fmt"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	peparser "github.com/saferwall/pe"
)

const (
	// name is the unique name of this extractor.
	name = "dotnet/pe"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	defaultMaxFileSizeBytes = 20 * units.MiB // 20 MB
)

// Config is the configuration for the .NET PE extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration of the extractor.
func DefaultConfig() Config {
	return Config{
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// New returns an .NET PE extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		cfg: cfg,
	}
}

type Extractor struct {
	cfg Config
}

// Ecosystem implements filesystem.Extractor.
func (e Extractor) Ecosystem(i *extractor.Inventory) string {
	return "NuGet"
}

// Extract parses the PE files to extract .NET package dependencies.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	// TODO: maybe use peparser.NewBytes here
	pe, err := peparser.New(input.Path, &peparser.Options{})
	if err != nil {
		return nil, err
	}

	ivs := []*extractor.Inventory{}

	// TODO: from my experience this step is redundant:
	// pe.CLR.MetadataTables seems to always contain an entry for the name and version of the current file
	//
	// solution:
	// 1. remove this step if it's actually always redundant
	// 2. add a deduplication pass (see `extractor/filesystem/language/golang/gomod/gomod.go` implementation) if not
	if versionResources, err := pe.ParseVersionResources(); err == nil {
		name, version := versionResources["InternalName"], versionResources["Assembly Version"]
		if name != "" && version != "" {
			ivs = append(ivs, &extractor.Inventory{
				Name:    name,
				Version: version,
			})
		}
	}

	for _, table := range pe.CLR.MetadataTables {
		switch content := table.Content.(type) {
		case []peparser.AssemblyTableRow:
			for _, v := range content {
				name := string(pe.GetStringFromData(v.Name, pe.CLR.MetadataStreams["#Strings"])) + ".dll"
				version := fmt.Sprintf("%d.%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber, v.RevisionNumber)
				ivs = append(ivs, &extractor.Inventory{
					Name:    name,
					Version: version,
				})
			}
			break
		case []peparser.AssemblyRefTableRow:
			for _, v := range content {
				name := string(pe.GetStringFromData(v.Name, pe.CLR.MetadataStreams["#Strings"])) + ".dll"
				version := fmt.Sprintf("%d.%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber, v.RevisionNumber)
				ivs = append(ivs, &extractor.Inventory{
					Name:    name,
					Version: version,
				})
			}
			break
		}
	}

	return ivs, nil
}

// FileRequired returns true if the specified file matches the .NET PE file structure.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()

	// TODO: maybe check for file extensions

	fileinfo, err := api.Stat()
	if err != nil || (e.cfg.MaxFileSizeBytes > 0 && fileinfo.Size() > e.cfg.MaxFileSizeBytes) {
		e.reportFileRequired(path, stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	// TODO: add magic bytes checks (don't know if this is the right time to open the file)

	return true
}

func (e Extractor) reportFileRequired(path string, result stats.FileRequiredResult) {
	if e.cfg.Stats == nil {
		return
	}
	e.cfg.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:   path,
		Result: result,
	})
}

// Name of the extractor.
func (e Extractor) Name() string {
	return name
}

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return &purl.PackageURL{
		Type:    purl.TypeNuget,
		Name:    i.Name,
		Version: i.Version,
	}
}

// Version of the extractor.
func (e Extractor) Version() int {
	return 0
}

var _ filesystem.Extractor = Extractor{}
