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

//go:build windows

// Package regosversion extracts the OS version (build, major, minor release) from the registry.
package regosversion

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/osv-scalibr/common/windows/registry"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/extractor/standalone/windows/common/metadata"
	"github.com/google/osv-scalibr/extractor/standalone/windows/common/winproducts"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the DISM patch level extractor
	Name           = "windows/regosversion"
	regVersionPath = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
)

// Configuration for the extractor.
type Configuration struct {
	// Opener is the registry engine to use (offline, live or mock).
	Opener registry.Opener
}

// DefaultConfiguration for the extractor. It uses the live registry of the running system.
func DefaultConfiguration() Configuration {
	return Configuration{
		Opener: registry.NewLiveOpener(),
	}
}

// Extractor provides a metadata extractor for the patch level on Windows.
type Extractor struct {
	opener registry.Opener
}

// New creates a new Extractor from a given configuration.
func New(config Configuration) standalone.Extractor {
	return &Extractor{
		opener: config.Opener,
	}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() standalone.Extractor {
	return New(DefaultConfiguration())
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{OS: plugin.OSWindows, RunningSystem: true}
}

// Extract the DISM patch level on Windows.
func (e *Extractor) Extract(ctx context.Context, input *standalone.ScanInput) (inventory.Inventory, error) {
	reg, err := e.opener.Open()
	if err != nil {
		return inventory.Inventory{}, err
	}
	defer reg.Close()

	key, err := reg.OpenKey("HKLM", regVersionPath)
	if err != nil {
		return inventory.Inventory{}, err
	}
	defer key.Close()

	currentVersion, err := e.windowsVersion(key)
	if err != nil {
		return inventory.Inventory{}, err
	}

	// CurrentBuildNumber should be available on a large range of Windows versions.
	buildNumber, err := key.ValueString("CurrentBuildNumber")
	if err != nil {
		return inventory.Inventory{}, err
	}

	revision, err := e.windowsRevision(key)
	if err != nil {
		return inventory.Inventory{}, err
	}

	flavor := winproducts.WindowsFlavorFromRegistry(reg)
	fullVersion := fmt.Sprintf("%s.%s.%s", currentVersion, buildNumber, revision)
	winproduct := winproducts.WindowsProductFromVersion(flavor, fullVersion)
	return inventory.Inventory{Packages: []*extractor.Package{
		{
			Name:     winproduct,
			Version:  fullVersion,
			PURLType: "windows",
			Metadata: &metadata.OSVersion{
				Product:     winproduct,
				FullVersion: fullVersion,
			},
		},
	}}, nil
}

// windowsVersion extracts the version of Windows (major and minor, e.g. 6.3 or 10.0)
func (e Extractor) windowsVersion(key registry.Key) (string, error) {
	// recent version of Windows
	majorVersion, majorErr := key.ValueString("CurrentMajorVersionNumber")
	minorVersion, minorErr := key.ValueString("CurrentMinorVersionNumber")

	if majorErr == nil && minorErr == nil {
		return fmt.Sprintf("%s.%s", majorVersion, minorVersion), nil
	}

	// older versions of Windows
	return key.ValueString("CurrentVersion")
}

// windowsRevision extracts the revision within the current build.
func (e Extractor) windowsRevision(key registry.Key) (string, error) {
	// recent version of Windows
	if revision, err := key.ValueString("UBR"); err == nil {
		return revision, nil
	}

	// on older version, we have to parse the BuildLabEx key
	buildLabEx, err := key.ValueString("BuildLabEx")
	if err != nil {
		return "", err
	}

	buildLabParts := strings.Split(buildLabEx, ".")
	if len(buildLabParts) < 2 {
		return "", fmt.Errorf("could not parse BuildLabEx: %q", buildLabEx)
	}

	return buildLabParts[1], nil
}
