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

// Package dockercomposeimage extracts image URLs from Docker Compose files.
package dockercomposeimage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/compose-spec/compose-go/v2/dotenv"
	"github.com/compose-spec/compose-go/v2/interpolation"
	"github.com/compose-spec/compose-go/v2/loader"
	"github.com/compose-spec/compose-go/v2/template"
	"github.com/compose-spec/compose-go/v2/tree"
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

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false.
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the extractor.
func DefaultConfig() Config {
	return Config{
		MaxFileSizeBytes: DefaultMaxFileSizeBytes,
	}
}

// Extractor extracts image URLs from Docker Compose files.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Docker Compose image extractor.
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

// FileRequired returns true if the specified file could be a Docker Compose file.
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
	filename := filepath.Base(path)
	if filepath.Ext(filename) != ".yml" && filepath.Ext(filename) != ".yaml" {
		return false
	}
	return strings.HasPrefix(filename, "compose") ||
		strings.HasPrefix(filename, "docker-compose")
}

// Extract extracts image URLs from a Docker Compose file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input.Info == nil {
		return inventory.Inventory{}, errors.New("input.Info is nil")
	}

	data, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}

	// Check for a top-level "services" field.
	var content map[string]any
	if err := yaml.Unmarshal(data, &content); err != nil {
		// Not a valid yaml file, not an error.
		return inventory.Inventory{}, err
	}
	if _, ok := content["services"]; !ok {
		// Not a compose file, not an error.
		return inventory.Inventory{}, nil
	}

	images, err := uniqueImagesFromReader(ctx, input)
	if err != nil {
		log.Warnf("Parsing docker-compose file %q failed: %v", input.Path, err)
		return inventory.Inventory{}, nil
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

// uniqueImagesFromReader extracts unique image names from a Docker Compose file.
// It handles environment variable interpolation and returns a sorted list of unique images.
func uniqueImagesFromReader(ctx context.Context, input *filesystem.ScanInput) ([]string, error) {
	absPath, err := input.GetRealPath()
	if err != nil {
		return nil, fmt.Errorf("GetRealPath(%v): %w", input, err)
	}
	if input.Root == "" {
		// The file got copied to a temporary dir, remove it at the end.
		defer func() {
			dir := filepath.Dir(absPath)
			if err := os.RemoveAll(dir); err != nil {
				log.Errorf("os.RemoveAll(%q): %v", dir, err)
			}
		}()
	}

	// Load environment variables from a sibling .env file if it exists
	workingDir := filepath.Dir(input.Path)
	envPath := filepath.ToSlash(filepath.Join(workingDir, ".env"))
	environment := types.Mapping{}
	if f, err := input.FS.Open(envPath); err == nil {
		defer f.Close()
		if envVars, err := dotenv.Parse(f); err != nil {
			log.Warnf("dotenv.Parse(%q): %v", envPath, err)
		} else {
			for k, v := range envVars {
				environment[k] = v
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Warnf("input.FS.Open(%q): %v", envPath, err)
	}
	configFiles := []types.ConfigFile{
		{Filename: absPath},
	}
	details := types.ConfigDetails{
		WorkingDir:  workingDir,
		ConfigFiles: configFiles,
		Environment: environment,
	}
	customOpts := loader.Options{
		Interpolate: &interpolation.Options{
			Substitute:      substitute,
			LookupValue:     details.LookupEnv,
			TypeCastMapping: make(map[tree.Path]interpolation.Cast),
		},
		ResolvePaths: true,
	}
	project, err := loader.LoadWithContext(
		ctx,
		details,
		func(opts *loader.Options) {
			*opts = customOpts
		})
	if err != nil {
		return nil, err
	}

	uniq := map[string]struct{}{}
	// We Skip services with an empty image version.
	// An empty image version is not a valid image reference.
	// This happened because some environment variables are not resolved
	for _, s := range project.Services {
		if s.Image != "" && !strings.Contains(s.Image, "<IMPERFECT_ENV_VAR_RESOLVING>") {
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

// parseName extracts the name and version from an image reference.
// It handles both digest format (name@digest) and tag format (name:tag).
// If no version is specified, it returns "latest" as the default version.
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

// substitute replaces environment variables in template strings with their values.
// For missing variables, it inserts a placeholder "<IMPERFECT_ENV_VAR_RESOLVING>" to indicate
// that the substitution was incomplete, allowing processing to continue.
func substitute(inTemplate string, mapping template.Mapping) (string, error) {
	options := []template.Option{
		template.WithPattern(template.DefaultPattern),
		template.WithReplacementFunction(
			func(substring string, mapping template.Mapping, cfg *template.Config) (string, error) {
				value, _, err := template.DefaultReplacementAppliedFunc(substring, mapping, cfg)
				if err != nil {
					return "", err
				}
				if value == "" {
					// Use placeholder for unresolved variables
					value = "<IMPERFECT_ENV_VAR_RESOLVING>"
				}
				return value, nil
			}),
	}

	return template.SubstituteWithOptions(inTemplate, mapping, options...)
}
