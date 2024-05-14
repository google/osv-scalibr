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

// Package cos extracts OS packages from Container Optimized OSes (go/cos).
package cos

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"

	extractor "github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/cos"
)

// Extractor extracts cos packages from cos database.
type Extractor struct{}

// cosPackage represents a COS package found in /etc/cos-package-info.json
type cosPackage struct {
	Category      string `json:"category"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	EbuildVersion string `json:"ebuild_version"`
}

// cosPackageInfo are packages found in /etc/cos-package-info.json.
type cosPackageInfo struct {
	InstalledPackages []cosPackage `json:"installedPackages"`
	BuildTimePackages []cosPackage `json:"buildTimePackages"`
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// FileRequired returns true if the specified file matches cos package info file pattern.
func (e Extractor) FileRequired(path string, _ fs.FileMode) bool {
	return path == "etc/cos-package-info.json"
}

// Extract extracts packages from cos package info files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *extractor.ScanInput) ([]*extractor.Inventory, error) {
	m, err := osrelease.GetOSRelease(input.ScanRoot)
	if err != nil {
		log.Errorf("osrelease.ParseOsRelease(): %v", err)
	}
	dec := json.NewDecoder(input.Reader)
	var packages cosPackageInfo
	if err := dec.Decode(&packages); err != nil {
		err := fmt.Errorf("failed to json decode %q: %v", input.Path, err)
		log.Debugf(err.Error())
		// TODO(b/281023532): We should not mark the overall SCALIBR scan as failed if we can't parse a file.
		return nil, fmt.Errorf("%w", err)
	}

	log.Infof("Found %d installed packages", len(packages.InstalledPackages))
	log.Infof("Found %d build time packages", len(packages.BuildTimePackages))

	inventory := []*extractor.Inventory{}
	for _, pkg := range packages.InstalledPackages {
		i := &extractor.Inventory{
			Name:    pkg.Name,
			Version: pkg.Version,
			Metadata: &Metadata{
				Name:        pkg.Name,
				Version:     pkg.Version,
				Category:    pkg.Category,
				OSVersion:   m["VERSION"],
				OSVersionID: m["VERSION_ID"],
			},
			Locations: []string{input.Path},
			Extractor: e.Name(),
		}
		inventory = append(inventory, i)
	}

	return inventory, nil
}

func toDistro(m *Metadata) string {
	if m.OSVersionID != "" {
		return fmt.Sprintf("cos-%s", m.OSVersionID)
	}

	if m.OSVersion != "" {
		log.Warnf("VERSION_ID not set in os-release, fallback to VERSION")
		return fmt.Sprintf("cos-%s", m.OSVersion)
	}
	log.Errorf("VERSION and VERSION_ID not set in os-release")
	return ""
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	m := i.Metadata.(*Metadata)
	q := map[string]string{}
	distro := toDistro(m)
	if distro != "" {
		q[purl.Distro] = distro
	}
	return &purl.PackageURL{
		Type:       purl.TypeCOS,
		Name:       i.Name,
		Version:    i.Version,
		Qualifiers: purl.QualifiersFromMap(q),
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }
