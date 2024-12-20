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

// Package nix extracts packages from the Nix store directory.
package nix

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/nix"
)

var (
	// visitedDir tracks already visited directories.
	visitedDir = make(map[string]bool)
)

// Extractor extracts packages from the nix store directory.
type Extractor struct{}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if a given path corresponds to a unique, unprocessed
// directory under the nixStoreDir path.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()

	if !strings.HasPrefix(path, "nix/store/") {
		return false
	}

	pathParts := strings.Split(path, "/")
	if len(pathParts) <= 3 {
		return false
	}

	// e.g.
	// path: nix/store/1ddf3x30m0z6kknmrmapsc7liz8npi1w-perl-5.38.2/bin/ptar
	// uniquePath: 1ddf3x30m0z6kknmrmapsc7liz8npi1w-perl-5.38.2
	uniquePath := pathParts[2]

	// Check if the uniquePath has already been processed
	if _, exists := visitedDir[uniquePath]; exists {
		return false
	}

	visitedDir[uniquePath] = true
	return true
}

var packageStoreRegex = regexp.MustCompile(`^([a-zA-Z0-9]{32})-([a-zA-Z0-9.-]+)-([0-9.]+)(?:-(\S+))?$`)
var packageStoreUnstableRegex = regexp.MustCompile(`^([a-zA-Z0-9]{32})-([a-zA-Z0-9.-]+)-(unstable-[0-9]{4}-[0-9]{2}-[0-9]{2})$`)

// Extract extracts packages from the filenames of the directories in the nix
// store path.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	// Check for cancellation or timeout.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%s halted at %q because of context error: %v", e.Name(), input.Path, err)
	}

	m, err := osrelease.GetOSRelease(input.FS)
	if err != nil {
		log.Errorf("osrelease.GetOSRelease(): %v", err)
	}

	pkg := strings.Split(input.Path, "/")[2]

	var matches []string
	if strings.Contains(pkg, "unstable") {
		matches = packageStoreUnstableRegex.FindStringSubmatch(pkg)
	} else {
		matches = packageStoreRegex.FindStringSubmatch(pkg)
	}

	if len(matches) == 0 {
		return nil, nil
	}

	pkgHash := matches[1]
	pkgName := matches[2]
	pkgVersion := matches[3]
	if pkgHash == "" || pkgName == "" || pkgVersion == "" {
		log.Warnf("NIX package name/version/hash is empty (name: %v, version: %v, hash: %v)", pkgName, pkgVersion, pkgHash)
		return nil, nil
	}

	i := &extractor.Inventory{
		Name:    pkgName,
		Version: pkgVersion,
		Metadata: &Metadata{
			PackageName:       pkgName,
			PackageVersion:    pkgVersion,
			PackageHash:       pkgHash,
			OSID:              m["ID"],
			OSVersionCodename: m["VERSION_CODENAME"],
			OSVersionID:       m["VERSION_ID"],
		},
		Locations: []string{input.Path},
	}

	if len(matches) > 4 {
		pkgOutput := matches[4]
		i.Metadata.(*Metadata).PackageOutput = pkgOutput
	}

	return []*extractor.Inventory{i}, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	m := i.Metadata.(*Metadata)
	q := map[string]string{}
	distro := toDistro(m)

	if distro != "" {
		q[purl.Distro] = distro
	}

	return &purl.PackageURL{
		Type:       purl.TypeNix,
		Name:       i.Name,
		Version:    i.Version,
		Qualifiers: purl.QualifiersFromMap(q),
	}
}

// Ecosystem returns no Ecosystem since the ecosystem is not known by OSV yet.
func (Extractor) Ecosystem(i *extractor.Inventory) string { return "" }

func toDistro(m *Metadata) string {
	if m.OSVersionCodename != "" {
		return m.OSVersionCodename
	}

	if m.OSVersionID != "" {
		return m.OSVersionID
	}

	log.Errorf("VERSION_CODENAME and VERSION_ID not set in os-release")

	return ""
}
