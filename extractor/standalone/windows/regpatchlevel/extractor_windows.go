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

// Package regpatchlevel extract patch level from the Windows registry.
package regpatchlevel

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"golang.org/x/sys/windows/registry"
)

const (
	// Registry path to the Windows component based servicing packages.
	regPackagesRoot = `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages`
)

var (
	dismVersionRegexp = regexp.MustCompile(`~([^~]+)$`)
	errSkipEntry      = errors.New("entry was skipped")
)

// Name of the extractor
const Name = "windows/regpatchlevel"

// Extractor implements the regpatchlevel extractor.
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
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, regPackagesRoot, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(0)
	if err != nil {
		return nil, err
	}

	var inventory []*extractor.Inventory

	for _, subkey := range subkeys {
		entry, err := e.handleKey(regPackagesRoot, subkey)
		if err != nil {
			if err == errSkipEntry {
				continue
			}

			return nil, err
		}

		inventory = append(inventory, entry)
	}

	return inventory, nil
}

func (e *Extractor) handleKey(registryPath, keyName string) (*extractor.Inventory, error) {
	keyPath := fmt.Sprintf("%s\\%s", registryPath, keyName)
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	currentState, _, err := key.GetIntegerValue("CurrentState")
	if err != nil {
		return nil, err
	}

	visibility, _, err := key.GetIntegerValue("Visibility")
	if err != nil {
		return nil, err
	}

	// Is installed and visible
	if (currentState != 0x70 && currentState != 0x50) || visibility != 1 {
		return nil, errSkipEntry
	}

	submatch := dismVersionRegexp.FindStringSubmatch(keyName)
	if len(submatch) < 2 {
		return nil, errSkipEntry
	}

	return &extractor.Inventory{
		Name:      keyName,
		Version:   submatch[1],
		Locations: []string{"windows-registry"},
	}, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return &purl.PackageURL{
		Type:      purl.TypeGeneric,
		Namespace: "microsoft",
		Name:      i.Name,
		Version:   i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

// Ecosystem returns a synthetic ecosystem since the Inventory is not a software package.
func (Extractor) Ecosystem(i *extractor.Inventory) (string, error) {
	return "Registry patch level", nil
}
