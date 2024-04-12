// Copyright 2024 Google LLC
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

// Package packagejson extracts package.json files.
package packagejson

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/internal/units"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/packagejson"

	// defaultMaxJSONSize is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxJSONSize = 100 * units.MiB
)

type packageJSON struct {
	Version      string    `json:"version"`
	Name         string    `json:"name"`
	Engines      any       `json:"engines"`
	Author       *Person   `json:"author"`
	Maintainers  []*Person `json:"maintainers"`
	Contributors []*Person `json:"contributors"`
	// Not an NPM field but present for VSCode Extension Manifest files.
	Contributes *struct {
	} `json:"contributes"`
}

// Config is the configuration for the Extractor.
type Config struct {
	// MaxJSONSize is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	MaxJSONSize int64
}

// DefaultConfig returns the default configuration for the package.json extractor.
func DefaultConfig() Config {
	return Config{
		MaxJSONSize: defaultMaxJSONSize,
	}
}

// Extractor extracts javascript packages from package.json files.
type Extractor struct {
	maxJSONSize int64
}

// New returns a package.json extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		maxJSONSize: cfg.MaxJSONSize,
	}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// FileRequired returns true if the specified file matches javascript Metadata file
// patterns.
func (e Extractor) FileRequired(path string, _ fs.FileMode) bool {
	return filepath.Base(path) == "package.json"
}

// Extract extracts packages from package.json files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *extractor.ScanInput) ([]*extractor.Inventory, error) {
	if input.Info != nil && input.Info.Size() > e.maxJSONSize {
		return nil, fmt.Errorf("package.json file %s is too large: %d", input.Path, input.Info.Size())
	}
	i, err := parse(input.Path, input.Reader)
	if err != nil {
		return nil, fmt.Errorf("packagejson.parse(%s): %w", input.Path, err)
	}
	if i == nil {
		return []*extractor.Inventory{}, nil
	}

	i.Locations = []string{input.Path}
	i.Extractor = e.Name()
	return []*extractor.Inventory{i}, nil
}

func parse(path string, r io.Reader) (*extractor.Inventory, error) {
	dec := json.NewDecoder(r)

	var p packageJSON
	if err := dec.Decode(&p); err != nil {
		log.Debugf("package.json file %s json decode failed: %v", path, err)
		// TODO(b/281023532): We should not mark the overall SCALIBR scan as failed if we can't parse a file.
		return nil, fmt.Errorf("failed to parse package.json file: %w", err)
	}

	if !p.hasNameAndVersionValues() {
		log.Debugf("package.json file %s does not have a version and/or name", path)
		return nil, nil
	}
	if p.isVSCodeExtension() {
		log.Debugf("package.json file %s is a Visual Studio Code Extension Manifest, not an NPM package", path)
		return nil, nil
	}

	return &extractor.Inventory{
		Name:    p.Name,
		Version: p.Version,
		Metadata: &JavascriptPackageJSONMetadata{
			Author:       p.Author,
			Maintainers:  removeEmptyPersons(p.Maintainers),
			Contributors: removeEmptyPersons(p.Contributors),
		},
	}, nil
}

func (p packageJSON) hasNameAndVersionValues() bool {
	return p.Name != "" && p.Version != ""
}

// isVSCodeExtension returns true if p is a VSCode Extension Manifest.
//
// Visual Studio Code uses package.lock files as manifest files for extensions:
// https://code.visualstudio.com/api/references/extension-manifest
// These files are similar to NPM package.lock:
// https://docs.npmjs.com/cli/v10/configuring-npm/package-json
// The `engine` field exists in both but is required to contain `vscode` in the extension.
// The `contributes` field is not required but only exists for VSCode extensions.
func (p packageJSON) isVSCodeExtension() bool {
	if e, ok := p.Engines.(map[string]any); ok {
		if _, ok := e["vscode"]; ok {
			return true
		}
	}
	return p.Contributes != nil
}

func removeEmptyPersons(persons []*Person) []*Person {
	var result []*Person
	for _, p := range persons {
		if p.Name != "" {
			result = append(result, p)
		}
	}
	return result
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return &purl.PackageURL{
		Type:    purl.TypeNPM,
		Name:    strings.ToLower(i.Name),
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }
