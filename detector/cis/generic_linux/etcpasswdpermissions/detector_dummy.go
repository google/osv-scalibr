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

//go:build !linux && !darwin

package etcpasswdpermissions

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/google/osv-scalibr/detector"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventoryindex"
	"github.com/google/osv-scalibr/plugin"
)

// Detector is a SCALIBR Detector for the CIS check "Ensure permissions on /etc/passwd- are configured"
// from the CIS Distribution Independent Linux benchmarks.
type Detector struct{}

// Name of the detector.
func (Detector) Name() string { return "cis/generic_linux/etcpasswdpermissions" }

// Version of the detector.
func (Detector) Version() int { return 0 }

// Requirements of the detector.
func (Detector) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// RequiredExtractors returns an empty list as there are no dependencies.
func (Detector) RequiredExtractors() []string { return []string{} }

// Scan is a no-op for Windows.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, ix *inventoryindex.InventoryIndex) ([]*detector.Finding, error) {
	return nil, fmt.Errorf("plugin only supported on Linux")
}

// ScanFS starts the scan from a pseudo-filesystem.
func (Detector) ScanFS(ctx context.Context, fs fs.FS, ix *inventoryindex.InventoryIndex) ([]*detector.Finding, error) {
	return nil, fmt.Errorf("plugin only supported on Linux")
}
