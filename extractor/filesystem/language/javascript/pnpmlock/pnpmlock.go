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

// Package pnpmlock extracts pnpm-lock.yaml files.
package pnpmlock

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/internal/commitextractor"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"gopkg.in/yaml.v3"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/pnpmlock"
)

type pnpmLockPackageResolution struct {
	Tarball string `yaml:"tarball"`
	Commit  string `yaml:"commit"`
	Repo    string `yaml:"repo"`
	Type    string `yaml:"type"`
}

type pnpmLockPackage struct {
	Resolution pnpmLockPackageResolution `yaml:"resolution"`
	Name       string                    `yaml:"name"`
	Version    string                    `yaml:"version"`
	Dev        bool                      `yaml:"dev"`
}

// pnpmImporterDependency is a single entry under an importer's "dependencies",
// "optionalDependencies" or "devDependencies" map in a v9+ lockfile.
type pnpmImporterDependency struct {
	Specifier string `yaml:"specifier"`
	Version   string `yaml:"version"`
}

// pnpmImporter is a single workspace project listed under the top-level
// "importers" key of a v9+ lockfile (a single-project repo only has one
// importer, keyed by "."). This is where a v9+ lockfile records whether a
// dependency was requested for production or for development use — unlike
// v6/v8, the "packages" section of a v9+ lockfile no longer carries a "dev"
// flag on each resolved package.
type pnpmImporter struct {
	Dependencies         map[string]pnpmImporterDependency `yaml:"dependencies"`
	OptionalDependencies map[string]pnpmImporterDependency `yaml:"optionalDependencies"`
	DevDependencies      map[string]pnpmImporterDependency `yaml:"devDependencies"`
}

// pnpmSnapshot is a single entry under the top-level "snapshots" key of a
// v9+ lockfile: the resolved dependency graph edges for one specific
// (package, peer-dependency resolution) pair. Snapshot keys are formatted as
// "name@version" with zero or more "(peerName@peerVersion)" suffixes, e.g.
// "tsutils@3.21.0(typescript@4.9.5)".
type pnpmSnapshot struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

type pnpmLockfile struct {
	Version   float64                    `yaml:"lockfileVersion"`
	Packages  map[string]pnpmLockPackage `yaml:"packages,omitempty"`
	Importers map[string]pnpmImporter    `yaml:"importers,omitempty"`
	Snapshots map[string]pnpmSnapshot    `yaml:"snapshots,omitempty"`
}

type pnpmLockfileV6 struct {
	Version   string                     `yaml:"lockfileVersion"`
	Packages  map[string]pnpmLockPackage `yaml:"packages,omitempty"`
	Importers map[string]pnpmImporter    `yaml:"importers,omitempty"`
	Snapshots map[string]pnpmSnapshot    `yaml:"snapshots,omitempty"`
}

// UnmarshalYAML is a custom unmarshalling function for handling v6 lockfiles.
func (l *pnpmLockfile) UnmarshalYAML(unmarshal func(any) error) error {
	var lockfileV6 pnpmLockfileV6

	if err := unmarshal(&lockfileV6); err != nil {
		return err
	}

	parsedVersion, err := strconv.ParseFloat(lockfileV6.Version, 64)

	if err != nil {
		return err
	}

	l.Version = parsedVersion
	l.Packages = lockfileV6.Packages
	l.Importers = lockfileV6.Importers
	l.Snapshots = lockfileV6.Snapshots

	return nil
}

var (
	numberMatcher = regexp.MustCompile(`^\d`)
	// Looks for the pattern "name@version", where name is allowed to contain zero or more "@"
	nameVersionRegexp = regexp.MustCompile(`^(.+)@([\w.-]+)(?:\(|$)`)

	codeLoadURLRegexp = regexp.MustCompile(`https://codeload\.github\.com(?:/[\w-.]+){2}/tar\.gz/(\w+)$`)
)

// extractPnpmPackageNameAndVersion parses a dependency path, attempting to
// extract the name and version of the package it represents
func extractPnpmPackageNameAndVersion(dependencyPath string, lockfileVersion float64) (string, string, error) {
	// file dependencies must always have a name property to be installed,
	// and their dependency path never has the version encoded, so we can
	// skip trying to extract either from their dependency path
	if strings.HasPrefix(dependencyPath, "file:") {
		return "", "", nil
	}

	// v9.0 specifies the dependencies as <package>@<version> rather than as a path
	if lockfileVersion >= 9.0 {
		dependencyPath = strings.Trim(dependencyPath, "'")
		dependencyPath, isScoped := strings.CutPrefix(dependencyPath, "@")

		name, version, _ := strings.Cut(dependencyPath, "@")

		if isScoped {
			name = "@" + name
		}

		return name, version, nil
	}

	parts := strings.Split(dependencyPath, "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid dependency path: %v", dependencyPath)
	}
	var name string

	parts = parts[1:]

	if strings.HasPrefix(parts[0], "@") {
		name = strings.Join(parts[:2], "/")
		parts = parts[2:]
	} else {
		name = parts[0]
		parts = parts[1:]
	}

	version := ""

	if len(parts) != 0 {
		version = parts[0]
	}

	if version == "" {
		name, version = parseNameAtVersion(name)
	}

	if version == "" || !numberMatcher.MatchString(version) {
		return "", "", nil
	}

	underscoreIndex := strings.Index(version, "_")

	if underscoreIndex != -1 {
		version = strings.Split(version, "_")[0]
	}

	return name, version, nil
}

func parseNameAtVersion(value string) (name string, version string) {
	matches := nameVersionRegexp.FindStringSubmatch(value)

	if len(matches) != 3 {
		return name, ""
	}

	return matches[1], matches[2]
}

// snapshotPeerSuffix matches everything from the first "(peer@version)" group
// (if any) to the end of a snapshots-section key, so that stripping it turns
// a resolved snapshot key such as "tsutils@3.21.0(typescript@4.9.5)" back
// into the bare "name@version" form used as a packages-section key.
var snapshotPeerSuffix = regexp.MustCompile(`\(.*$`)

// snapshotKeyFor builds the snapshots-section key that a "name" -> "version"
// dependency edge (as found in an importer's dependency maps, or in another
// snapshot's own dependency map) resolves to.
func snapshotKeyFor(name, version string) string {
	return name + "@" + version
}

// bareSnapshotKey strips any peer-dependency suffix from a snapshots-section
// key, turning it into the plain "name@version" form used as a
// packages-section key.
func bareSnapshotKey(key string) string {
	return snapshotPeerSuffix.ReplaceAllString(key, "")
}

// collectDevOnlyPackages walks the dependency graph recorded in a v9+
// lockfile's "snapshots" section to determine which resolved packages are
// reachable *only* through a devDependency, and never through a production
// dependency (direct or transitive, in any workspace project). It returns
// the set of bare "name@version" packages-section keys that should be
// reported with the "dev" dependency group.
//
// This graph walk exists because, starting with lockfileVersion 9.0, pnpm no
// longer writes a computed "dev: true" flag on every transitively-dev
// package in the "packages" section (see
// https://github.com/google/osv-scanner/issues/1298) — dev/production
// status is only recorded once, on each workspace's direct dependencies in
// "importers", and has to be propagated through "snapshots" by hand.
func collectDevOnlyPackages(lockfile pnpmLockfile) map[string]bool {
	var walk func(key string, reached map[string]bool)
	walk = func(key string, reached map[string]bool) {
		if reached[key] {
			return
		}
		reached[key] = true

		snapshot, ok := lockfile.Snapshots[key]
		if !ok {
			return
		}
		for name, version := range snapshot.Dependencies {
			walk(snapshotKeyFor(name, version), reached)
		}
		for name, version := range snapshot.OptionalDependencies {
			walk(snapshotKeyFor(name, version), reached)
		}
	}

	prodReachable := map[string]bool{}
	devReachable := map[string]bool{}

	for _, importer := range lockfile.Importers {
		for name, dep := range importer.Dependencies {
			walk(snapshotKeyFor(name, dep.Version), prodReachable)
		}
		for name, dep := range importer.OptionalDependencies {
			walk(snapshotKeyFor(name, dep.Version), prodReachable)
		}
	}
	for _, importer := range lockfile.Importers {
		for name, dep := range importer.DevDependencies {
			walk(snapshotKeyFor(name, dep.Version), devReachable)
		}
	}

	devOnly := map[string]bool{}
	for key := range devReachable {
		devOnly[bareSnapshotKey(key)] = true
	}
	// The same package can appear as several snapshots, one per distinct
	// peer-dependency resolution. If any variation of it is reachable from
	// a production dependency, the package as a whole is not dev-only.
	for key := range prodReachable {
		delete(devOnly, bareSnapshotKey(key))
	}

	return devOnly
}

func parsePnpmLock(lockfile pnpmLockfile, packageLineMap map[string]int, path string) ([]*extractor.Package, error) {
	packages := make([]*extractor.Package, 0, len(lockfile.Packages))
	errs := []error{}

	// The "dev" flag on each packages-section entry was removed from the
	// lockfile format in lockfileVersion 9.0; for those lockfiles dev/prod
	// status has to be recomputed from the snapshot graph instead.
	var devOnlyPackages map[string]bool
	if lockfile.Version >= 9.0 {
		devOnlyPackages = collectDevOnlyPackages(lockfile)
	}

	for s, pkg := range lockfile.Packages {
		name, version, err := extractPnpmPackageNameAndVersion(s, lockfile.Version)
		if err != nil {
			errs = append(errs, err)
			log.Errorf("failed to extract package version from %v: %v", pkg, err)
			continue
		}

		// "name" is only present if it's not in the dependency path and takes
		// priority over whatever name we think we've extracted (if any)
		if pkg.Name != "" {
			name = pkg.Name
		}

		// "version" is only present if it's not in the dependency path and takes
		// priority over whatever version we think we've extracted (if any)
		if pkg.Version != "" {
			version = pkg.Version
		}

		if name == "" || version == "" {
			continue
		}

		commit := pkg.Resolution.Commit

		if strings.HasPrefix(pkg.Resolution.Tarball, "https://codeload.github.com") {
			matched := codeLoadURLRegexp.FindStringSubmatch(pkg.Resolution.Tarball)

			if matched != nil {
				commit = matched[1]
			}
		}

		repo := ""
		if commit != "" {
			if pkg.Resolution.Repo != "" {
				repo = commitextractor.NormalizeRepo(pkg.Resolution.Repo)
			} else if pkg.Resolution.Tarball != "" {
				repo = commitextractor.NormalizeRepo(pkg.Resolution.Tarball)
			}
		}

		purlType := purl.TypeNPM
		if commit != "" {
			purlType = purl.TypeGit
		}

		depGroups := []string{}
		if lockfile.Version >= 9.0 {
			if devOnlyPackages[s] {
				depGroups = append(depGroups, "dev")
			}
		} else if pkg.Dev {
			depGroups = append(depGroups, "dev")
		}

		lineNum := packageLineMap[s]
		packages = append(packages, &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purlType,
			SourceCode: &extractor.SourceCodeIdentifier{
				Commit: commit,
				Repo:   repo,
			},
			Metadata: &osv.DepGroupMetadata{
				DepGroupVals: depGroups,
			},
			Location: extractor.LocationFromPathAndLine(path, lineNum),
		})
	}

	return packages, errors.Join(errs...)
}

// Extractor extracts pnpm-lock.yaml files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches pnpm-lock.yaml files.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "pnpm-lock.yaml" {
		return false
	}
	// Skip lockfiles inside node_modules directories since the packages they list aren't
	// necessarily installed by the root project. We instead use the more specific top-level
	// lockfile for the root project dependencies.
	dir := filepath.ToSlash(filepath.Dir(path))
	return !slices.Contains(strings.Split(dir, "/"), "node_modules")
}

// Extract extracts packages from a pnpm-lock.yaml file passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	dec := yaml.NewDecoder(input.Reader)
	var allPackages []*extractor.Package
	var errs []error

	for {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{Packages: allPackages}, err
		}

		var root yaml.Node
		if err := dec.Decode(&root); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return inventory.Inventory{Packages: allPackages}, fmt.Errorf("could not extract: %w", err)
		}

		var parsedLockfile pnpmLockfile
		if err := root.Decode(&parsedLockfile); err != nil {
			return inventory.Inventory{Packages: allPackages}, fmt.Errorf("could not extract: %w", err)
		}

		packageLineMap := findLineNumbers(&root)

		packages, err := parsePnpmLock(parsedLockfile, packageLineMap, input.Path)
		if err != nil {
			errs = append(errs, err)
		}
		allPackages = append(allPackages, packages...)
	}

	if allPackages == nil {
		allPackages = []*extractor.Package{}
	}

	return inventory.Inventory{Packages: allPackages}, errors.Join(errs...)
}

// findLineNumbers goes through the Node tree to find the line numbers for each package.
func findLineNumbers(root *yaml.Node) map[string]int {
	results := make(map[string]int)
	if len(root.Content) == 0 {
		return results
	}
	doc := root.Content[0]

	if doc.Kind != yaml.MappingNode {
		return results // empty results
	}

	var packagesNode *yaml.Node
	// Note: increment by 2 to iterate from key to key (skip the value).
	for i := 0; i < len(doc.Content); i += 2 {
		if doc.Content[i].Value == "packages" {
			packagesNode = doc.Content[i+1]
			break
		}
	}

	if packagesNode == nil || packagesNode.Kind != yaml.MappingNode {
		return results // empty results
	}
	// Note: increment by 2 to iterate from key to key (skip the value).
	for i := 0; i < len(packagesNode.Content); i += 2 {
		keyNode := packagesNode.Content[i]
		results[keyNode.Value] = keyNode.Line
	}
	return results
}

var _ filesystem.Extractor = Extractor{}
