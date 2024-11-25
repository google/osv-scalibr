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

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"golang.org/x/sys/windows/registry"
)

const (
	// regUninstallRootWow64 is the registry key for 32-bit software on 64-bit Windows.
	regUninstallRootWow64     = `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
	regUninstallRootDefault   = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	regUninstallRelativeUsers = `Software\Microsoft\Windows\CurrentVersion\Uninstall`

	// googetPrefix identifies GooGet packages.
	googetPrefix = "GooGet -"
)

// Name of the extractor
const Name = "windows/ospackages"

// Extractor implements the ospackages extractor.
type Extractor struct{}

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

	inventory := e.allSoftwaresInfo(registry.LOCAL_MACHINE, sysKeys)

	// Then we extract user-level installed software.
	userKeys, err := e.installedUserSoftware()
	if err != nil {
		return nil, err
	}

	inv := e.allSoftwaresInfo(registry.USERS, userKeys)
	return append(inventory, inv...), nil
}

// allSoftwaresInfo builds the inventory of name/version for installed software from the given registry
// keys. This function cannot return an error.
func (e *Extractor) allSoftwaresInfo(key registry.Key, paths []string) []*extractor.Inventory {
	var inventory []*extractor.Inventory

	for _, p := range paths {
		// Silently swallow errors as some software might not have a name or version.
		// For example, paint will be a subkey of the registry key, but it does not have a version.
		if inv, err := e.softwareInfo(key, p); err == nil {
			inventory = append(inventory, inv)
		}
	}

	return inventory
}

func (e *Extractor) softwareInfo(key registry.Key, path string) (*extractor.Inventory, error) {
	key, err := registry.OpenKey(key, path, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	name, _, err := key.GetStringValue("DisplayName")
	if err != nil {
		return nil, err
	}

	version, _, err := key.GetStringValue("DisplayVersion")
	if err != nil {
		return nil, err
	}

	return &extractor.Inventory{
		Name:    name,
		Version: version,
	}, nil
}

func (e *Extractor) installedSystemSoftware() ([]string, error) {
	keys, err := e.enumerateSubkeys(registry.LOCAL_MACHINE, regUninstallRootDefault)
	if err != nil {
		return nil, err
	}

	k, err := e.enumerateSubkeys(registry.LOCAL_MACHINE, regUninstallRootWow64)
	if err != nil {
		return nil, err
	}

	return append(keys, k...), nil
}

func (e *Extractor) installedUserSoftware() ([]string, error) {
	var keys []string

	userHives, err := e.enumerateSubkeys(registry.USERS, "")
	if err != nil {
		return nil, err
	}

	for _, userHive := range userHives {
		regPath := fmt.Sprintf(`%s\%s`, userHive, regUninstallRelativeUsers)
		regPath = strings.TrimPrefix(regPath, `\`)

		// Note that the key might not exist or be accessible for all users, so we silently ignore
		// errors here.
		if k, err := e.enumerateSubkeys(registry.USERS, regPath); err == nil {
			keys = append(keys, k...)
		}
	}

	return keys, nil
}

func (e *Extractor) enumerateSubkeys(key registry.Key, path string) ([]string, error) {
	key, err := registry.OpenKey(key, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(0)
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
