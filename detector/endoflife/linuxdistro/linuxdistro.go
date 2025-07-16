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

// Package linuxdistro implements a detector for End-of-Life Linux distributions
package linuxdistro

import (
	"context"
	"time"

	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the detector.
	Name = "endoflife/linuxdistro"
)

var now = time.Now

// Detector is a SCALIBR Detector for End-Of-Life linux distributions
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
func (Detector) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{OS: plugin.OSLinux}
}

// RequiredExtractors returns nothing (no deps).
func (Detector) RequiredExtractors() []string { return []string{} }

func eolFinding(target *inventory.GenericFindingTargetDetails) inventory.Finding {
	title := "End-of-Life operating system"
	description := "The system is running a Linux distribution that has reached end-of-life " +
		"(EOL) and is no longer maintained by the vendor. This means it no longer " +
		"receives security updates or patches."
	recommendation := "Upgrade the operating system to a supported release or arrange " +
		"an extended support with the vendor."
	return inventory.Finding{GenericFindings: []*inventory.GenericFinding{{
		Adv: &inventory.GenericFindingAdvisory{
			ID: &inventory.AdvisoryID{
				Publisher: "SCALIBR",
				Reference: "linux-end-of-life",
			},
			Title:          title,
			Description:    description,
			Recommendation: recommendation,
			Sev:            inventory.SeverityCritical,
		},
		Target: target,
	}}}
}

var eolDetector = map[string]func(map[string]string, scalibrfs.FS) bool{
	"fedora": fedoraEOL,
	"ubuntu": ubuntuEOL,
}

// Scan checks for the presence of an end-of-life Linux OS on the host.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	osRelease, err := osrelease.GetOSRelease(scanRoot.FS)
	if err != nil {
		return inventory.Finding{}, err
	}
	distro, ok := osRelease["ID"]
	if !ok {
		return inventory.Finding{}, err
	}
	if detector, ok := eolDetector[distro]; ok {
		if detector(osRelease, scanRoot.FS) {
			target := &inventory.GenericFindingTargetDetails{Extra: "distro: " + distro}
			return eolFinding(target), nil
		}
	}
	return inventory.Finding{}, nil
}

// DetectedFinding returns generic vulnerability information about what is detected.
func (d Detector) DetectedFinding() inventory.Finding {
	return eolFinding(nil)
}
