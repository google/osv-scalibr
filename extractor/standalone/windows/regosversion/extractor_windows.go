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

//go:build windows

// Package regosversion extracts the OS version (build, major, minor release) from the registry.
package regosversion

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/extractor/standalone/windows/common/winproducts"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name of the DISM patch level extractor
	Name           = "windows/regosversion"
	regVersionPath = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
)

// Extractor provides a metadata extractor for the DISM patch level on Windows.
type Extractor struct{}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Extract the DISM patch level on Windows.
func (e *Extractor) Extract(ctx context.Context, input *standalone.ScanInput) ([]*extractor.Inventory, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, regVersionPath, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	currentVersion, err := e.windowsVersion(key)
	if err != nil {
		return nil, err
	}

	// CurrentBuildNumber should be available on a large range of Windows versions.
	buildNumber, _, err := key.GetStringValue("CurrentBuildNumber")
	if err != nil {
		return nil, err
	}

	revision, err := e.windowsRevision(key)
	if err != nil {
		return nil, err
	}

	flavor := winproducts.WindowsFlavorFromRegistry()
	fullVersion := fmt.Sprintf("%s.%s.%d", currentVersion, buildNumber, revision)
	winproduct := winproducts.WindowsProductFromVersion(flavor, fullVersion)
	return []*extractor.Inventory{
		&extractor.Inventory{
			Name:      winproduct,
			Version:   fullVersion,
			Locations: []string{"registry"},
		},
	}, nil
}

// windowsVersion extracts the version of Windows (major and minor, e.g. 6.3 or 10.0)
func (e Extractor) windowsVersion(key registry.Key) (string, error) {
	// recent version of Windows
	majorVersion, _, majorErr := key.GetIntegerValue("CurrentMajorVersionNumber")
	minorVersion, _, minorErr := key.GetIntegerValue("CurrentMinorVersionNumber")

	if majorErr == nil && minorErr == nil {
		return fmt.Sprintf("%d.%d", majorVersion, minorVersion), nil
	}

	// older versions of Windows
	version, _, err := key.GetStringValue("CurrentVersion")
	return version, err
}

// windowsRevision extracts the revision within the current build.
func (e Extractor) windowsRevision(key registry.Key) (uint64, error) {
	// recent version of Windows
	if revision, _, err := key.GetIntegerValue("UBR"); err == nil {
		return revision, nil
	}

	// on older version, we have to parse the BuildLabEx key
	buildLabEx, _, err := key.GetStringValue("BuildLabEx")
	if err != nil {
		return 0, err
	}

	buildLabParts := strings.Split(buildLabEx, ".")
	if len(buildLabParts) < 2 {
		return 0, fmt.Errorf("could not parse BuildLabEx: %q", buildLabEx)
	}

	return strconv.ParseUint(buildLabParts[1], 10, 64)
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return &purl.PackageURL{
		Type:      purl.TypeGeneric,
		Namespace: "microsoft",
		Name:      i.Name,
		Qualifiers: purl.QualifiersFromMap(map[string]string{
			purl.BuildNumber: i.Version,
		}),
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }
