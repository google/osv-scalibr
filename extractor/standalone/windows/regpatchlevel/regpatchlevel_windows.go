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

//go:build windows

// Package regpatchlevel extract patch level from the Windows registry.
package regpatchlevel

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/osv-scalibr/common/windows/registry"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
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
type Extractor struct {
	Opener registry.Opener
}

// New returns a new instance of the extractor.
func New(cfg *cpb.PluginConfig) (standalone.Extractor, error) {
	return &Extractor{Opener: registry.NewLiveOpener()}, nil
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
	reg, err := e.Opener.Open()
	if err != nil {
		return inventory.Inventory{}, err
	}
	defer reg.Close()

	key, err := reg.OpenKey("HKLM", regPackagesRoot)
	if err != nil {
		return inventory.Inventory{}, err
	}
	defer key.Close()

	subkeys, err := key.SubkeyNames()
	if err != nil {
		return inventory.Inventory{}, err
	}

	var pkgs []*extractor.Package

	for _, subkey := range subkeys {
		entry, err := e.handleKey(reg, regPackagesRoot, subkey)
		if err != nil {
			if errors.Is(err, errSkipEntry) {
				continue
			}

			return inventory.Inventory{}, err
		}

		pkgs = append(pkgs, entry)
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

func (e *Extractor) handleKey(reg registry.Registry, registryPath, keyName string) (*extractor.Package, error) {
	keyPath := fmt.Sprintf("%s\\%s", registryPath, keyName)
	key, err := reg.OpenKey("HKLM", keyPath)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	currentState, err := key.ValueString("CurrentState")
	if err != nil {
		return nil, err
	}

	visibility, err := key.ValueString("Visibility")
	if err != nil {
		return nil, err
	}

	// Is installed and visible
	if (currentState != "112" && currentState != "80") || visibility != "1" {
		return nil, errSkipEntry
	}

	submatch := dismVersionRegexp.FindStringSubmatch(keyName)
	if len(submatch) < 2 {
		return nil, errSkipEntry
	}

	return &extractor.Package{
		Name:     keyName,
		Version:  submatch[1],
		PURLType: "windows",
	}, nil
}
