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

//go:build !linux

// Package pammisconfig implements a detector for PAM (Pluggable Authentication Modules)
// misconfigurations that could lead to authentication bypass or privilege escalation.
package pammisconfig

import (
	"context"
	"io/fs"

	"github.com/google/osv-scalibr/detector"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the detector.
	Name = "misc/pammisconfig"
)

// Detector is a SCALIBR Detector for PAM misconfiguration vulnerabilities.
type Detector struct{}

// New returns a new PAM misconfiguration detector.
func New() detector.Detector {
	return &Detector{}
}

// Name of the detector.
func (Detector) Name() string { return Name }

// Version of the detector.
func (Detector) Version() int { return 0 }

// RequiredExtractors returns an empty list as there are no dependencies.
func (Detector) RequiredExtractors() []string { return []string{} }

// Requirements of the Detector.
func (Detector) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// Scan starts the scan.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	return d.ScanFS(ctx, scanRoot.FS, px)
}

// DetectedFinding returns generic vulnerability information about what is detected.
func (Detector) DetectedFinding() inventory.Finding {
	return findingForTarget(nil)
}

func findingForTarget(target *inventory.GenericFindingTargetDetails) inventory.Finding {
	return inventory.Finding{GenericFindings: []*inventory.GenericFinding{{
		Adv: &inventory.GenericFindingAdvisory{
			ID: &inventory.AdvisoryID{
				Publisher: "SCALIBR",
				Reference: "pam-authentication-bypass",
			},
			Title: "PAM Configuration Allows Authentication Bypass",
			Description: "Misconfigured PAM (Pluggable Authentication Modules) stack permits " +
				"unauthorized login. This can occur when permissive modules like pam_permit.so " +
				"are used as 'sufficient' in the auth stack, when pam_succeed_if.so bypasses " +
				"authentication with broad conditions, or when nullok allows empty passwords. " +
				"Attackers can exploit these misconfigurations to gain unauthorized access " +
				"to SSH, sudo, console login, and other PAM-protected services.",
			Recommendation: "Review and secure PAM configurations in /etc/pam.d/: " +
				"1) Remove or restrict pam_permit.so usage in auth stacks, " +
				"2) Avoid pam_succeed_if.so as 'sufficient' with broad conditions, " +
				"3) Remove 'nullok' option from authentication modules to prevent empty password login, " +
				"4) Ensure proper 'required' modules like pam_unix.so are present. " +
				"Test changes with pamtester before applying to production.",
			Sev: inventory.SeverityCritical,
		},
		Target: target,
	}}}
}

// ScanFS starts the scan from a pseudo-filesystem.
// This detector only works on Linux systems (PAM is Linux-specific).
func (d Detector) ScanFS(ctx context.Context, fsys fs.FS, px *packageindex.PackageIndex) (inventory.Finding, error) {
	return inventory.Finding{}, nil
}
