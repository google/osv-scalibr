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

// Package packagejson extracts package.json files.
package packagejson

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"slices"

	"deps.dev/util/semver"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/internal/linefinder"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/tidwall/gjson"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
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
	Version      string             `json:"version"`
	Name         string             `json:"name"`
	Engines      any                `json:"engines"`
	Author       *metadata.Person   `json:"author"`
	Maintainers  []*metadata.Person `json:"maintainers"`
	Contributors []*metadata.Person `json:"contributors"`
	// Not an NPM field but present for VSCode Extension Manifest files.
	Contributes *struct {
	} `json:"contributes"`
	// Not an NPM field but present for Unity package files.
	Unity                string            `json:"unity"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type dependencyConfig struct {
	includeDependencies         bool
	includeDevDependencies      bool
	includeOptionalDependencies bool
	includePeerDependencies     bool
}

type dependencyDetails struct {
	pkg       *extractor.Package
	depGroups []string
}

// Extractor extracts javascript packages from package.json files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
	depConfig        dependencyConfig
}

// New returns a package.json extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	depConfig := dependencyConfig{}
	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.JavascriptPackageJsonConfig {
		return c.GetJavascriptPackageJson()
	})
	if specific != nil {
		if specific.GetMaxFileSizeBytes() > 0 {
			maxFileSizeBytes = specific.GetMaxFileSizeBytes()
		}
		depConfig.includeDependencies = specific.GetIncludeDependencies()
		depConfig.includeDevDependencies = specific.GetIncludeDevDependencies()
		depConfig.includeOptionalDependencies = specific.GetIncludeOptionalDependencies()
		depConfig.includePeerDependencies = specific.GetIncludePeerDependencies()
	}

	return &Extractor{
		maxFileSizeBytes: maxFileSizeBytes,
		depConfig:        depConfig,
	}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches javascript Metadata file
// patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "package.json" {
		return false
	}

	fileinfo, err := api.Stat()
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
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts packages from package.json files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := parse(input.Path, input.Reader, e.depConfig)
	if err != nil {
		e.reportFileExtracted(input.Path, input.Info, err)
		return inventory.Inventory{}, fmt.Errorf("packagejson.parse: %w", err)
	}

	e.reportFileExtracted(input.Path, input.Info, nil)
	return inventory.Inventory{Packages: pkgs}, nil
}

func (e Extractor) reportFileExtracted(path string, fileinfo fs.FileInfo, err error) {
	if e.Stats == nil {
		return
	}
	var fileSizeBytes int64
	if fileinfo != nil {
		fileSizeBytes = fileinfo.Size()
	}
	e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
		Path:          path,
		Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
		FileSizeBytes: fileSizeBytes,
	})
}

// parse parses a package.json file and returns a list of packages.
func parse(path string, r io.Reader, depConfig dependencyConfig) ([]*extractor.Package, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	finder := linefinder.NewJSONLineFinder(string(content))

	var p packageJSON
	if err := json.Unmarshal(content, &p); err != nil {
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

	var pkgs []*extractor.Package

	// Find the line number of the root "name" key.
	// This "root" package is extracted separately from the other package dependencies.
	nameLine := finder.LineOf("name")
	if nameLine == 0 {
		// This should never happen because SCALIBR will not extract a package.json
		// file that does not have a "name" key.
		log.Debugf("could not find line number for name field in package.json file %s", path)
	}

	rootLoc := extractor.LocationFromPath(path)
	rootLoc.Descriptor.File.LineNumber = nameLine

	pkgs = append(pkgs, &extractor.Package{
		Name:     p.Name,
		Version:  p.Version,
		PURLType: purl.TypeNPM,
		Location: rootLoc,
		Metadata: &metadata.JavascriptPackageJSONMetadata{
			Author:       p.Author,
			Maintainers:  removeEmptyPersons(p.Maintainers),
			Contributors: removeEmptyPersons(p.Contributors),
		},
	})

	depPkgs := map[string]dependencyDetails{}
	if depConfig.includeDependencies {
		addDependencyPackages(depPkgs, path, finder, "dependencies", p.Dependencies, nil)
	}
	if depConfig.includeDevDependencies {
		addDependencyPackages(depPkgs, path, finder, "devDependencies", p.DevDependencies, []string{"dev"})
	}
	if depConfig.includeOptionalDependencies {
		addDependencyPackages(depPkgs, path, finder, "optionalDependencies", p.OptionalDependencies, []string{"optional"})
	}
	if depConfig.includePeerDependencies {
		addDependencyPackages(depPkgs, path, finder, "peerDependencies", p.PeerDependencies, []string{"peer"})
	}

	for _, dep := range depPkgs {
		dep.pkg.Metadata = &osv.DepGroupMetadata{DepGroupVals: dep.depGroups}
		pkgs = append(pkgs, dep.pkg)
	}

	return pkgs, nil
}

// addDependencyPackages parses dependency entries and adds them to pkgs.
// pkgs accumulates packages keyed by "name@version" so duplicate entries across
// dependency sections can be merged. path is the package.json path used for logs
// and locations. finder maps JSON fields back to line numbers. field is the JSON
// dependency section, such as "dependencies" or "devDependencies". deps maps
// package names to version constraints from that section. depGroups is the OSV
// dependency-group metadata to apply, with nil/empty meaning production.
func addDependencyPackages(pkgs map[string]dependencyDetails, path string, finder *linefinder.JSONLineFinder, field string, deps map[string]string, depGroups []string) {
	for name, constraint := range deps {
		c, err := semver.NPM.ParseConstraint(constraint)
		if err != nil {
			log.Debugf("failed to parse NPM version constraint %s for dependency %s in %s: %v", constraint, name, path, err)
			continue
		}
		v, err := c.CalculateMinVersion()
		if err != nil {
			log.Debugf("failed to calculate min NPM version for dependency %s in %s with constraint %s: %v", name, path, constraint, err)
			continue
		}

		lineNum := finder.LineOf(field + "." + gjson.Escape(name))
		// Need to use Canon() to rebuild the string with the changes from CalculateMinVersion.
		// Ignoring the build value, which isn't relevant for version comparison.
		// TODO(b/444684673): Include the build value in the version string. Currently deps.dev
		// does not parse out the build value, so that need to be fixed first.
		version := v.Canon(false)
		key := name + "@" + version
		pkg := &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purl.TypeNPM,
			Location: extractor.LocationFromPathAndLine(path, lineNum),
		}

		current := dependencyDetails{pkg: pkg, depGroups: depGroups}
		existing, ok := pkgs[key]
		if !ok {
			pkgs[key] = current
			continue
		}
		pkgs[key] = mergeDependencyDetails(existing, current)
	}
}

// mergeDependencyDetails merges two package.json entries for the same package
// name and version. existing is the entry already added from a previous
// dependency section, and current is the entry being added now. Empty depGroups
// means production and takes precedence over dev/optional/peer groups; otherwise
// non-production groups are combined and sorted.
func mergeDependencyDetails(existing, current dependencyDetails) dependencyDetails {
	if len(existing.depGroups) == 0 {
		return existing
	}
	if len(current.depGroups) == 0 {
		return current
	}

	merged := append(slices.Clone(existing.depGroups), current.depGroups...)
	slices.Sort(merged)
	existing.depGroups = slices.Compact(merged)
	return existing
}

func (p packageJSON) hasNameAndVersionValues() bool {
	return p.Name != "" && p.Version != ""
}

// isVSCodeExtension returns true if p is a VSCode Extension Manifest.
//
// Visual Studio Code uses package.lock files as manifest files for extensions:
// https://code.visualstudio.com/api/references/extension-manifest
// These files are similar to NPM package.lock:
// https://docs.npmjs.com/cli/v10/configuring-npm/package.jsonn
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

func removeEmptyPersons(persons []*metadata.Person) []*metadata.Person {
	var result []*metadata.Person
	for _, p := range persons {
		if p.Name != "" {
			result = append(result, p)
		}
	}
	return result
}
