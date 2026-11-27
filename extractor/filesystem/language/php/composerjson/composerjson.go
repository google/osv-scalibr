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

// Package composerjson extracts composer.json files.
package composerjson

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "php/composerjson"

	// maxPackageJSONSizeBytes limits the size of a single composer.json file
	maxPackageJSONSizeBytes int64 = 10 * units.MiB
)

type composerJSON struct {
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

// Extractor extracts composer.json files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches composer.json files.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "composer.json"
}

// Check whether the name refers to a platform pseudo-package
// These packages are not installed by Composer directly
// https://getcomposer.org/doc/01-basic-usage.md#platform-packages
func isPlatformPackage(name string) bool {
	if name == "php" || name == "hhvm" || name == "composer" {
		return true
	}
	return strings.HasPrefix(name, "php-") ||
		strings.HasPrefix(name, "ext-") ||
		strings.HasPrefix(name, "lib-") ||
		strings.HasPrefix(name, "composer-")
}

func buildPackage(input *filesystem.ScanInput, name string, constraint string, groups []string) (*extractor.Package, error) {
	version, err := getMinimumVersionForConstraint(constraint)
	if err != nil {
		return nil, fmt.Errorf("could not resolve version for %q from constraint %q: %w", name, constraint, err)
	}
	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purl.TypeComposer,
		Location: extractor.LocationFromPath(input.Path),
		Metadata: &osv.DepGroupMetadata{
			DepGroupVals: groups,
		},
	}, nil
}

// Extract extracts packages from a composer.json file passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedManifest *composerJSON

	// Prevent ingestion of large composer.json file
	limitReader := io.LimitReader(input.Reader, maxPackageJSONSizeBytes)
	err := json.NewDecoder(limitReader).Decode(&parsedManifest)

	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	if parsedManifest == nil {
		return inventory.Inventory{}, errors.New("could not extract: decoded null JSON value")
	}

	packages := make(
		[]*extractor.Package,
		0,
		uint64(len(parsedManifest.Require))+uint64(len(parsedManifest.RequireDev)),
	)

	for name, constraint := range parsedManifest.Require {
		if isPlatformPackage(name) {
			continue
		}
		pkg, err := buildPackage(input, name, constraint, []string{})
		if err != nil {
			log.Warnf("Skipping package: %v", err)
			continue
		}
		packages = append(packages, pkg)
	}

	for name, constraint := range parsedManifest.RequireDev {
		if isPlatformPackage(name) {
			continue
		}
		pkg, err := buildPackage(input, name, constraint, []string{"dev"})
		if err != nil {
			log.Warnf("Skipping package: %v", err)
			continue
		}
		packages = append(packages, pkg)
	}

	return inventory.Inventory{Packages: packages}, nil
}

var _ filesystem.Extractor = Extractor{}
