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

// Package dockerbaseimage extracts base image urls from Dockerfiles.
package dockerbaseimage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/moby/buildkit/frontend/dockerfile/linter"

	mbi "github.com/moby/buildkit/frontend/dockerfile/instructions"
	mbp "github.com/moby/buildkit/frontend/dockerfile/parser"
)

const (
	// Name is the unique name of this extractor.
	Name = "containers/dockerbaseimage"

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

// FileRequired returns true if the specified file matches Dockerfile.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	fileName := filepath.Base(api.Path())
	ext := filepath.Ext(fileName)
	baseName := strings.TrimSuffix(fileName, ext)
	return strings.ToLower(baseName) == "dockerfile" || strings.ToLower(ext) == ".dockerfile"
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

	stages, args, err := parse(input.Reader)
	if err != nil {
		log.Warnf("Parsing error: %v", err)
		return inventory.Inventory{}, err
	}

	argsMap := toMap(args)
	baseContainers := uniqueContainers(stages)

	var pkgs []*extractor.Package
	for _, container := range baseContainers {
		resolvedName := resolveName(container, argsMap)

		name, version := parseName(resolvedName)

		pkgs = append(pkgs, &extractor.Package{
			Locations: []string{input.Path},
			Name:      name,
			Version:   version,
			PURLType:  purl.TypeDocker,
		})
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

func resolveName(name string, argsMap map[string]string) string {
	if !strings.HasPrefix(name, "$") {
		return name
	}
	resolved := argsMap[strings.Trim(name, "${}")]
	if resolved == "" {
		return name
	}
	return resolved
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

func toMap(args []mbi.ArgCommand) map[string]string {
	m := make(map[string]string)
	for _, arg := range args {
		for _, arg := range arg.Args {
			if arg.Value != nil {
				m[arg.Key] = *arg.Value
			}
		}
	}
	return m
}

func uniqueContainers(stages []mbi.Stage) []string {
	stagesSeen := make(map[string]bool)
	containersSeen := make(map[string]bool)
	var baseContainers []string
	for _, stage := range stages {
		if slices.Contains(dockerBaseContainers, stage.BaseName) {
			// Skip base containers that are reserved or special values.
			continue
		}
		stagesSeen[stage.Name] = true
		if stagesSeen[stage.BaseName] {
			continue
		}
		baseContainer := stage.BaseName
		if containersSeen[baseContainer] {
			continue
		}
		baseContainers = append(baseContainers, baseContainer)
		containersSeen[baseContainer] = true
	}
	return baseContainers
}

func parse(r io.Reader) ([]mbi.Stage, []mbi.ArgCommand, error) {
	p, err := mbp.Parse(r)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse dockerfile: %w", err)
	}

	return mbi.Parse(p.AST, linter.New(&linter.Config{}))
}
