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

// Package ospackages extracts installed softwares on Windows.
package ospackages

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/osv-scalibr/common/windows/registry"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// regUninstallRootWow64 is the registry key for 32-bit software on 64-bit Windows.
	regUninstallRootWow64     = `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
	regUninstallRootDefault   = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	regUninstallRelativeUsers = `Software\Microsoft\Windows\CurrentVersion\Uninstall`

	// googetPrefix identifies GooGet packages.
	googetPrefix = "GooGet -"
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

// Name of the extractor
const Name = "windows/ospackages"

// Extractor implements the ospackages extractor.
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

// Extract retrieves the patch level from the Windows registry.
func (e *Extractor) Extract(ctx context.Context, input *standalone.ScanInput) (inventory.Inventory, error) {
	reg, err := e.opener.Open()
	if err != nil {
		return inventory.Inventory{}, err
	}

	defer reg.Close()

	// First extract the system-level installed software, both for x64 and x86.
	sysKeys, err := e.installedSystemSoftware(reg)
	if err != nil {
		return inventory.Inventory{}, err
	}

	pkg := e.allSoftwaresInfo(reg, "HKLM", sysKeys)

	// Then we extract user-level installed software.
	userKeys, err := e.installedUserSoftware(reg)
	if err != nil {
		return inventory.Inventory{}, err
	}

	pkgs := e.allSoftwaresInfo(reg, "HKU", userKeys)
	return inventory.Inventory{Packages: append(pkgs, pkg...)}, nil
}

// allSoftwaresInfo builds the package of name/version for installed software from the given registry
// keys. This function cannot return an error.
func (e *Extractor) allSoftwaresInfo(reg registry.Registry, hive string, paths []string) []*extractor.Package {
	var pkgs []*extractor.Package

	for _, p := range paths {
		// Silently swallow errors as some software might not have a name or version.
		// For example, paint will be a subkey of the registry key, but it does not have a version.
		if pkg, err := e.softwareInfo(reg, hive, p); err == nil {
			pkgs = append(pkgs, pkg)
		}
	}

	return pkgs
}

func (e *Extractor) softwareInfo(reg registry.Registry, hive string, path string) (*extractor.Package, error) {
	key, err := reg.OpenKey(hive, path)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	displayName, err := key.ValueString("DisplayName")
	if err != nil {
		return nil, err
	}

	displayVersion, err := key.ValueString("DisplayVersion")
	if err != nil {
		return nil, err
	}

	purlType := "windows"
	if strings.HasPrefix(displayName, googetPrefix) {
		purlType = purl.TypeGooget
	}
	return &extractor.Package{
		Name:     displayName,
		Version:  displayVersion,
		PURLType: purlType,
	}, nil
}

func (e *Extractor) installedSystemSoftware(reg registry.Registry) ([]string, error) {
	keys, err := e.enumerateSubkeys(reg, "HKLM", regUninstallRootDefault)
	if err != nil {
		return nil, err
	}

	k, err := e.enumerateSubkeys(reg, "HKLM", regUninstallRootWow64)
	if err != nil {
		return nil, err
	}

	return append(keys, k...), nil
}

func (e *Extractor) installedUserSoftware(reg registry.Registry) ([]string, error) {
	var keys []string

	userHives, err := e.enumerateSubkeys(reg, "HKU", "")
	if err != nil {
		return nil, err
	}

	for _, userHive := range userHives {
		regPath := fmt.Sprintf(`%s\%s`, userHive, regUninstallRelativeUsers)
		regPath = strings.TrimPrefix(regPath, `\`)

		// Note that the key might not exist or be accessible for all users, so we silently ignore
		// errors here.
		if k, err := e.enumerateSubkeys(reg, "HKU", regPath); err == nil {
			keys = append(keys, k...)
		}
	}

	return keys, nil
}

func (e *Extractor) enumerateSubkeys(reg registry.Registry, hive string, path string) ([]string, error) {
	key, err := reg.OpenKey(hive, path)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	subkeys, err := key.SubkeyNames()
	if err != nil {
		return nil, err
	}

	var paths []string
	for _, subkey := range subkeys {
		paths = append(paths, fmt.Sprintf(`%s\%s`, path, subkey))
	}

	return paths, nil
}
