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

// Package etcpasswdpermissions implements a detector for the "Ensure permissions on /etc/passwd- are configured" CIS check.
package etcpasswdpermissions

import (
	"context"
	"errors"
	"io/fs"

	"github.com/google/osv-scalibr/detector"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the detector.
	Name = "cis/generic-linux/etcpasswdpermissions"
)

// Detector is a SCALIBR Detector for the CIS check "Ensure permissions on /etc/passwd- are configured"
// from the CIS Distribution Independent Linux benchmarks.
type Detector struct{}

// New returns a detector.
func New() detector.Detector {
	return &Detector{}
}

// Name of the detector.
func (Detector) Name() string { return Name }

// Version of the detector.
func (Detector) Version() int { return 0 }

// Requirements of the detector.
func (Detector) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// RequiredExtractors returns an empty list as there are no dependencies.
func (Detector) RequiredExtractors() []string { return []string{} }

// DetectedFinding returns generic vulnerability information about what is detected.
func (d Detector) DetectedFinding() inventory.Finding {
	return inventory.Finding{GenericFindings: []*inventory.GenericFinding{{
		Adv: &inventory.GenericFindingAdvisory{
			ID: &inventory.AdvisoryID{
				Publisher: "CIS",
				Reference: "etc-passwd-permissions",
			},
			Title: "Ensure permissions on /etc/passwd are configured",
			Description: "The /etc/passwd file contains user account information that " +
				"is used by many system utilities and therefore must be readable for these " +
				"utilities to operate.",
			Recommendation: "Run the following command to set permissions on /etc/passwd :\n" +
				"# chown root:root /etc/passwd\n" +
				"# chmod 644 /etc/passwd",
			Sev: inventory.SeverityMinimal,
		},
	}}}
}

// Scan is a no-op for Windows.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	return inventory.Finding{}, errors.New("plugin only supported on Linux")
}

// ScanFS starts the scan from a pseudo-filesystem.
func (Detector) ScanFS(ctx context.Context, fs fs.FS, px *packageindex.PackageIndex) (inventory.Finding, error) {
	return inventory.Finding{}, errors.New("plugin only supported on Linux")
}
