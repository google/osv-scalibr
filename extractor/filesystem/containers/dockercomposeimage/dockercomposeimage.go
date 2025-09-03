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

// Package dockercomposeimage extracts base image urls from Dockerfiles.
package dockercomposeimage

import (
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/compose-spec/compose-go/v2/loader"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"gopkg.in/yaml.v3"
)

const (
	// Name is the unique name of this extractor.
	Name = "containers/dockercomposeimage"

	// DefaultMaxFileSizeBytes is the default maximum file size the extractor will
	// attempt to extract. If a file is encountered that is larger than this
	// limit, the file is ignored by `FileRequired`.
	DefaultMaxFileSizeBytes = 1 * units.MiB
)

var (
	// dockerBaseContainers is a list of reserved terms/base containers that can be used within a
	// Dockerfile (e.g. "scratch" is Docker's reserved, minimal image) and require special handling.
	dockerBaseContainers = []string{"scratch"}
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the extractor.
func DefaultConfig() Config {
	return Config{
		MaxFileSizeBytes: DefaultMaxFileSizeBytes,
	}
}

// Extractor extracts repository URLs from Dockerfiles.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Dockerfile repository extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:            cfg.Stats,
		maxFileSizeBytes: cfg.MaxFileSizeBytes,
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

// FileRequired returns true if the specified file matches Dockerfile.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	// Skip directories and oversized files
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return false
	}
	if e.maxFileSizeBytes > 0 && fi.Size() > e.maxFileSizeBytes {
		return false
	}

	// Parse YAML and look for top-level "services" field
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	dec := yaml.NewDecoder(io.LimitReader(f, e.maxFileSizeBytes))
	var content map[string]interface{}
	if err := dec.Decode(&content); err != nil {
		return false
	}
	_, ok := content["services"]
	return ok
}

// Extract extracts base image urls from a Dockerfile.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input.Info == nil {
		return inventory.Inventory{}, errors.New("input.Info is nil")
	}
	if input.Info.Size() > e.maxFileSizeBytes {
		// Skipping too large file.
		log.Infof("Skipping too large file: %s", input.Path)
		return inventory.Inventory{}, nil
	}

	images, err := UniqueImagesFromReader(ctx, input.Reader)
	if err != nil {
		log.Warnf("Parsing error: %v", err)
		return inventory.Inventory{}, err
	}
	var pkgs []*extractor.Package
	for _, image := range images {

		name, version := parseName(image)

		pkgs = append(pkgs, &extractor.Package{
			Locations: []string{input.Path},
			Name:      name,
			Version:   version,
			PURLType:  purl.TypeDocker,
		})
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

func UniqueImagesFromReader(
	ctx context.Context,
	r io.Reader,
) ([]string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	details := types.ConfigDetails{
		WorkingDir: "",
		ConfigFiles: []types.ConfigFile{
			{Filename: "in-memory.yaml", Content: data},
		},
	}

	project, err := loader.LoadWithContext(
		ctx,
		details,
	)
	if err != nil {
		return nil, err
	}

	uniq := map[string]struct{}{}
	for _, s := range project.Services {
		if s.Image != "" {
			uniq[s.Image] = struct{}{}
		}
	}

	out := make([]string, 0, len(uniq))
	for img := range uniq {
		out = append(out, img)
	}
	sort.Strings(out)
	return out, nil
}

func parseName(name string) (string, string) {
	if strings.Contains(name, "@") {
		parts := strings.SplitN(name, "@", 2)
		return parts[0], parts[1]
	}

	if strings.Contains(name, ":") {
		parts := strings.SplitN(name, ":", 2)
		return parts[0], parts[1]
	}

	return name, "latest"
}
