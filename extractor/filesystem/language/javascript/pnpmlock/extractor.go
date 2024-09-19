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

// Package pnpmlock extracts pnpm-lock.yaml files.
package pnpmlock

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-yaml/yaml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
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

type pnpmLockfile struct {
	Version  float64                    `yaml:"lockfileVersion"`
	Packages map[string]pnpmLockPackage `yaml:"packages,omitempty"`
}

type pnpmLockfileV6 struct {
	Version  string                     `yaml:"lockfileVersion"`
	Packages map[string]pnpmLockPackage `yaml:"packages,omitempty"`
}

// UnmarshalYAML is a custom unmarshaling function for handling v6 lockfiles.
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

	return nil
}

// PnpmEcosystem is the OSV ecpsystem for pnpm-lock.yaml files.
const PnpmEcosystem = "npm"

var (
	numberMatcher = regexp.MustCompile(`^\d`)
	// Looks for the pattern "name@version", where name is allowed to contain zero or more "@"
	nameVersionRegexp = regexp.MustCompile(`^(.+)@([\d.]+)$`)
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
		return "", "", fmt.Errorf("invalid depdendency path: %v", dependencyPath)
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

func parsePnpmLock(lockfile pnpmLockfile) ([]*extractor.Inventory, error) {
	packages := make([]*extractor.Inventory, 0, len(lockfile.Packages))
	errs := []error{}

	for s, pkg := range lockfile.Packages {
		name, version, err := extractPnpmPackageNameAndVersion(s, lockfile.Version)
		if err != nil {
			errs = append(errs, err)
			log.Errorf("failed to extract package version from %q: %v", pkg, err)
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
			re := regexp.MustCompile(`https://codeload\.github\.com(?:/[\w-.]+){2}/tar\.gz/(\w+)$`)
			matched := re.FindStringSubmatch(pkg.Resolution.Tarball)

			if matched != nil {
				commit = matched[1]
			}
		}

		depGroups := []string{}
		if pkg.Dev {
			depGroups = append(depGroups, "dev")
		}

		packages = append(packages, &extractor.Inventory{
			Name:    name,
			Version: version,
			SourceCode: &extractor.SourceCodeIdentifier{
				Commit: commit,
			},
			Metadata: osv.DepGroupMetadata{
				DepGroupVals: depGroups,
			},
		})
	}

	return packages, errors.Join(errs...)
}

// Extractor extracts pnpm-lock.yaml files.
type Extractor struct{}

// Name of the extractor
func (e Extractor) Name() string { return "javascript/pnpmlock" }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches pnpm-lock.yaml files.
func (e Extractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "pnpm-lock.yaml"
}

// Extract extracts packages from a pnpm-lock.yaml file passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockfile *pnpmLockfile

	err := yaml.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil && !errors.Is(err, io.EOF) {
		return []*extractor.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	// this will happen if the file is empty
	if parsedLockfile == nil {
		parsedLockfile = &pnpmLockfile{}
	}

	inventories, err := parsePnpmLock(*parsedLockfile)
	for i := range inventories {
		inventories[i].Locations = []string{input.Path}
	}

	return inventories, err
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

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
func (e Extractor) Ecosystem(i *extractor.Inventory) (string, error) {
	return PnpmEcosystem, nil
}

var _ filesystem.Extractor = Extractor{}
