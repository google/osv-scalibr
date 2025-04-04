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

// Package detector provides the interface for security-related detection plugins.
package detector

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"
)

// Detector is the interface for a security detector plugin, used to scan for security findings
// such as vulnerabilities.
type Detector interface {
	plugin.Plugin
	// RequiredExtractors returns a list of Extractors that need to be enabled for this
	// Detector to run.
	RequiredExtractors() []string
	// Scan performs the security scan, considering scanRoot to be the root directory.
	// Implementations may use PackageIndex to check if a relevant software package is installed and
	// terminate early if it's not.
	Scan(c context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) ([]*Finding, error)
}

// LINT.IfChange

// Finding is the security finding found by a detector. It could describe things like a CVE or a CIS non-compliance.
// TODO(b/400910349): Move from detector into a separate package such as inventory.
type Finding struct {
	// Info specific to the finding. Should always be the same for the same type of finding.
	Adv *Advisory
	// Instance-specific info such as location of the vulnerable files.
	Target *TargetDetails
	// Additional free-text info.
	Extra string
	// The name of the Detectors that found this finding. Set by the core library.
	Detectors []string
}

// Advisory describes a security finding and how to remediate it. It should not contain any
// information specific to the target (e.g. which files were found vulnerable).
type Advisory struct {
	// A unique ID for the finding.
	ID   *AdvisoryID
	Type TypeEnum
	// Title, short description and recommendation steps for the finding. Users should be able to rely
	// on these fields to understand the vulnerability and remediate it.
	// Title of the finding, e.g. "CVE-2024-1234 - RCE Vulnerability on Foo".
	Title string
	// Description of the finding, e.g. "Foo prior to version 1.2.3 is affected by a Remote Code
	// Execution vulnerability.".
	Description string
	// Recommendation for how to remediate the finding, e.g. "Upgrade Foo to version 1.2.4 or
	// higher.".
	Recommendation string
	Sev            *Severity
}

// TypeEnum describes what kind of security finding this is.
// For now the only type is "Vulnerability".
type TypeEnum int

// TypeEnum values.
const (
	TypeUnknown TypeEnum = iota
	TypeVulnerability
	TypeCISFinding
)

// AdvisoryID is a unique identifier per advisory.
type AdvisoryID struct {
	Publisher string // e.g. "CVE".
	Reference string // e.g. "CVE-2023-1234".
}

// Severity of the vulnerability.
type Severity struct {
	// Required severity enum. Can be used for e.g. prioritizing filed bugs.
	Severity SeverityEnum
	// Optional CVSS scores, only set for vulns with CVEs.
	CVSSV2 *CVSS
	CVSSV3 *CVSS
}

// CVSS contains the CVSS scores for the finding.
type CVSS struct {
	BaseScore          float32
	TemporalScore      float32
	EnvironmentalScore float32
}

// SeverityEnum is an enum-based representation of the finding's severity. Some findings don't have
// a CVE associated so we use this enum instead to signal the urgency of the remediation.
type SeverityEnum int

// SeverityEnum values.
const (
	SeverityUnspecified SeverityEnum = iota
	SeverityMinimal
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// TargetDetails contains instance-specific details about the security finding.
type TargetDetails struct {
	// The software affected by the finding. Taken from the Package extraction results.
	Package *extractor.Package
	// Location of vulnerable files not related to the package,
	// e.g. config files with misconfigurations.
	Location []string
}

// LINT.ThenChange(/binary/proto/scan_result.proto)

// Run runs the specified detectors and returns their findings,
// as well as info about whether the plugin runs completed successfully.
func Run(ctx context.Context, c stats.Collector, detectors []Detector, scanRoot *scalibrfs.ScanRoot, index *packageindex.PackageIndex) ([]*Finding, []*plugin.Status, error) {
	findings := []*Finding{}
	status := []*plugin.Status{}
	for _, d := range detectors {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		start := time.Now()
		results, err := d.Scan(ctx, scanRoot, index)
		c.AfterDetectorRun(d.Name(), time.Since(start), err)
		for _, f := range results {
			f.Detectors = []string{d.Name()}
		}
		findings = append(findings, results...)
		status = append(status, plugin.StatusFromErr(d, false, err))
	}
	if err := validateAdvisories(findings); err != nil {
		return []*Finding{}, status, err
	}
	return findings, status, nil
}

func validateAdvisories(findings []*Finding) error {
	// Check that findings with the same advisory ID have identical advisories.
	ids := make(map[AdvisoryID]Advisory)
	for _, f := range findings {
		if f.Adv == nil {
			return fmt.Errorf("finding has no advisory set: %v", f)
		}
		if f.Adv.ID == nil {
			return fmt.Errorf("finding has no advisory ID set: %v", f)
		}
		if adv, ok := ids[*f.Adv.ID]; ok {
			if !reflect.DeepEqual(adv, *f.Adv) {
				return fmt.Errorf("multiple non-identical advisories with ID %v", f.Adv.ID)
			}
		}
		ids[*f.Adv.ID] = *f.Adv
	}
	return nil
}
