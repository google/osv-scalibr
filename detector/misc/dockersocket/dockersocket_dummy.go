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

// Package dockersocket implements a detector for Docker socket exposure vulnerabilities.
package dockersocket

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
	Name = "dockersocket"
)

// Detector is a SCALIBR Detector for Docker socket exposure vulnerabilities.
type Detector struct{}

// New returns a detector.
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
func (Detector) Requirements() *plugin.Capabilities { return &plugin.Capabilities{OS: plugin.OSUnix} }

// Scan starts the scan.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	return d.ScanFS(ctx, scanRoot.FS, px)
}

// DetectedFinding returns generic vulnerability information about what is detected.
func (d Detector) DetectedFinding() inventory.Finding {
	return d.findingForTarget(nil)
}

func (Detector) findingForTarget(target *inventory.GenericFindingTargetDetails) inventory.Finding {
	return inventory.Finding{GenericFindings: []*inventory.GenericFinding{{
		Adv: &inventory.GenericFindingAdvisory{
			ID: &inventory.AdvisoryID{
				Publisher: "SCALIBR",
				Reference: "docker-socket-exposure",
			},
			Title: "Docker Socket Exposure Detection",
			Description: "Docker socket exposure can lead to privilege escalation and container escape vulnerabilities. " +
				"Insecure Docker socket permissions, daemon configuration, or systemd service settings " +
				"may allow unauthorized access to the Docker API, potentially compromising the entire host system.",
			Recommendation: "Secure Docker socket by: 1) Setting appropriate file permissions (660) on /var/run/docker.sock, " +
				"2) Configuring daemon.json to use TLS authentication for remote API access, " +
				"3) Ensuring systemd service configurations use secure API bindings with proper authentication.",
			Sev: inventory.SeverityHigh,
		},
		Target: target,
	}}}
}

// ScanFS starts the scan from a pseudo-filesystem.
func (d Detector) ScanFS(ctx context.Context, fsys fs.FS, px *packageindex.PackageIndex) (inventory.Finding, error) {
	// This detector only works on Unix-like systems (not Windows)
	return inventory.Finding{}, nil
}
