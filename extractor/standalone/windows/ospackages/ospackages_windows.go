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

// Package ospackages extracts installed softwares on Windows.
package ospackages

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/osv-scalibr/common/windows/registry"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
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
	// Registry is the registry engine to use (offline, live or mock).
	Registry registry.Registry
}

// DefaultConfiguration for the extractor. It uses the live registry of the running system.
func DefaultConfiguration() Configuration {
	return Configuration{
		Registry: registry.NewLive(),
	}
}

// Name of the extractor
const Name = "windows/ospackages"

// Extractor implements the ospackages extractor.
type Extractor struct {
	registry registry.Registry
}

// New creates a new Extractor from a given configuration.
func New(config Configuration) *Extractor {
	return &Extractor{
		registry: config.Registry,
	}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{RunningSystem: true}
}

// Extract retrieves the patch level from the Windows registry.
func (e *Extractor) Extract(ctx context.Context, input *standalone.ScanInput) ([]*extractor.Inventory, error) {
	// First extract the system-level installed software, both for x64 and x86.
	sysKeys, err := e.installedSystemSoftware()
	if err != nil {
		return nil, err
	}

	inventory := e.allSoftwaresInfo("HKLM", sysKeys)

	// Then we extract user-level installed software.
	userKeys, err := e.installedUserSoftware()
	if err != nil {
		return nil, err
	}

	inv := e.allSoftwaresInfo("HKU", userKeys)
	return append(inventory, inv...), nil
}

// allSoftwaresInfo builds the inventory of name/version for installed software from the given registry
// keys. This function cannot return an error.
func (e *Extractor) allSoftwaresInfo(hive string, paths []string) []*extractor.Inventory {
	var inventory []*extractor.Inventory

	for _, p := range paths {
		// Silently swallow errors as some software might not have a name or version.
		// For example, paint will be a subkey of the registry key, but it does not have a version.
		if inv, err := e.softwareInfo(hive, p); err == nil {
			inventory = append(inventory, inv)
		}
	}

	return inventory
}

func (e *Extractor) softwareInfo(hive string, path string) (*extractor.Inventory, error) {
	key, err := e.registry.OpenKey(hive, path)
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

	return &extractor.Inventory{
		Name:    displayName,
		Version: displayVersion,
	}, nil
}

func (e *Extractor) installedSystemSoftware() ([]string, error) {
	keys, err := e.enumerateSubkeys("HKLM", regUninstallRootDefault)
	if err != nil {
		return nil, err
	}

	k, err := e.enumerateSubkeys("HKLM", regUninstallRootWow64)
	if err != nil {
		return nil, err
	}

	return append(keys, k...), nil
}

func (e *Extractor) installedUserSoftware() ([]string, error) {
	var keys []string

	userHives, err := e.enumerateSubkeys("HKU", "")
	if err != nil {
		return nil, err
	}

	for _, userHive := range userHives {
		regPath := fmt.Sprintf(`%s\%s`, userHive, regUninstallRelativeUsers)
		regPath = strings.TrimPrefix(regPath, `\`)

		// Note that the key might not exist or be accessible for all users, so we silently ignore
		// errors here.
		if k, err := e.enumerateSubkeys("HKU", regPath); err == nil {
			keys = append(keys, k...)
		}
	}

	return keys, nil
}

func (e *Extractor) enumerateSubkeys(hive string, path string) ([]string, error) {
	key, err := e.registry.OpenKey(hive, path)
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

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	if strings.HasPrefix(i.Name, googetPrefix) {
		return &purl.PackageURL{
			Type:    purl.TypeGooget,
			Name:    i.Name,
			Version: i.Version,
		}
	}

	return &purl.PackageURL{
		Type:      purl.TypeGeneric,
		Namespace: "microsoft",
		Name:      i.Name,
		Version:   i.Version,
	}
}

// Ecosystem returns no ecosystem since OSV does not support windows ospackages yet.
func (Extractor) Ecosystem(i *extractor.Inventory) string { return "" }
