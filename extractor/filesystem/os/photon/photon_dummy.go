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

// Package photon extracts packages from Photon OS RPM databases.
package photon

import (
	"context"
	"errors"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

// Name is the unique name of this extractor.
const Name = "os/photon"

// Extractor extracts Photon OS packages from the RPM database.
type Extractor struct {
	Stats stats.Collector
}

// New returns a Photon OS extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired always returns false as Photon OS extractor is not supported on Windows.
func (e Extractor) FileRequired(_ filesystem.FileAPI) bool {
	return false
}

// Extract is not supported on Windows.
func (e Extractor) Extract(_ context.Context, _ *filesystem.ScanInput) (inventory.Inventory, error) {
	return inventory.Inventory{}, errors.New("not supported")
}
