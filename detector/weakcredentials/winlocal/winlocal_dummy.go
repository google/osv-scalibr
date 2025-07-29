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

//go:build !windows

// Package winlocal implements a weak passwords detector for local accounts on Windows.
package winlocal

import (
	"context"
	"errors"

	"github.com/google/osv-scalibr/detector"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the detector.
	Name              = "weakcredentials/winlocal"
	vulnRefLMPassword = "PASSWORD_HASH_LM_FORMAT"
	vulnRefWeakPass   = "WINDOWS_WEAK_PASSWORD"
)

// Detector is a SCALIBR Detector for weak passwords detector for local accounts on Windows.
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
	return &plugin.Capabilities{OS: plugin.OSWindows}
}

// RequiredExtractors returns an empty list as there are no dependencies.
func (Detector) RequiredExtractors() []string { return nil }

// DetectedFinding returns generic vulnerability information about what is detected.
func (d Detector) DetectedFinding() inventory.Finding {
	return inventory.Finding{
		GenericFindings: []*inventory.GenericFinding{
			&inventory.GenericFinding{
				Adv: &inventory.GenericFindingAdvisory{
					ID: &inventory.AdvisoryID{
						Publisher: "GOOGLE",
						Reference: vulnRefLMPassword,
					},
					Title:          "Password hashes are stored in the LM format",
					Sev:            inventory.SeverityHigh,
					Description:    "Password hashes are stored in the LM format. Please switch local storage to use NT format and regenerate the hashes.",
					Recommendation: "Change the password of the user after changing the storage format.",
				},
			},
			&inventory.GenericFinding{
				Adv: &inventory.GenericFindingAdvisory{
					ID: &inventory.AdvisoryID{
						Publisher: "GOOGLE",
						Reference: vulnRefWeakPass,
					},
					Title:          "Weak passwords on Windows",
					Sev:            inventory.SeverityCritical,
					Description:    "Some passwords were identified as being weak.",
					Recommendation: "Change the password of the user affected users.",
				},
			},
		},
	}
}

// Scan starts the scan.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	return inventory.Finding{}, errors.New("only supported on Windows")
}
