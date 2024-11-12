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
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/packagejson"

	// defaultMaxFileSizeBytes is the default maximum file size the extractor will
	// attempt to extract. If a file is encountered that is larger than this
	// limit, the file is ignored by `FileRequired`.
	defaultMaxFileSizeBytes = 100 * units.MiB
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
	// Not an NPM field but present for Unity package files.
	Unity string `json:"unity"`
}

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum size of a file that can be extracted.
	// If this limit is greater than zero and a file is encountered that is larger
	// than this limit, the file is ignored by returning false for `FileRequired`.
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the package.json extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor extracts javascript packages from package.json files.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a package.json extractor.
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

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches javascript Metadata file
// patterns.
func (e Extractor) FileRequired(path string, stat func() (fs.FileInfo, error)) bool {
	if filepath.Base(path) != "package.json" {
		return false
	}

	fileinfo, err := stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.stats == nil {
		return
	}
	e.stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts packages from package.json files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	i, err := parse(input.Path, input.Reader)
	if err != nil {
		e.reportFileExtracted(input.Path, input.Info, err)
		return nil, fmt.Errorf("packagejson.parse(%s): %w", input.Path, err)
	}

	inventory := []*extractor.Inventory{}
	if i != nil {
		inventory = append(inventory, i)
		i.Locations = []string{input.Path}
	}

	e.reportFileExtracted(input.Path, input.Info, nil)
	return inventory, nil
}

func (e Extractor) reportFileExtracted(path string, fileinfo fs.FileInfo, err error) {
	if e.stats == nil {
		return
	}
	var fileSizeBytes int64
	if fileinfo != nil {
		fileSizeBytes = fileinfo.Size()
	}
	e.stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
		Path:          path,
		Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
		FileSizeBytes: fileSizeBytes,
	})
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
	if p.isUnityPackage() {
		log.Debugf("package.json file %s is a Unity package, not an NPM package", path)
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

// isUnityPackage returns true if p is a Unity package.
//
// Unity (https://docs.unity3d.com/Manual/upm-manifestPkg.html) packages
// are similar to NPM packages in that they use the same filename share some of
// the core fields such as name and version.
// They also have a "unity" field that lists the Unity version. we can use
// this to differentiate them from NPM packages.
func (p packageJSON) isUnityPackage() bool {
	return p.Unity != ""
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
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return &purl.PackageURL{
		Type:    purl.TypeNPM,
		Name:    strings.ToLower(i.Name),
		Version: i.Version,
	}
}

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
// OSV requires the name field to be a npm package. This is a javascript extractor, there is no
// guarantee that the package is an npm package.
func (Extractor) Ecosystem(i *extractor.Inventory) string { return "npm" }
