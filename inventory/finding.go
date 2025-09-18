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

package inventory

import (
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// LINT.IfChange

// Finding is a struct returned by Detectors that contains all security finding
// related inventory types.
type Finding struct {
	PackageVulns    []*PackageVuln
	GenericFindings []*GenericFinding
}

// LINT.ThenChange(/detector/detectorrunner/detectorrunner.go)

// LINT.IfChange

// PackageVuln is a vulnerability (e.g. a CVE) related to a package.
// It follows the OSV Schema format: https://ossf.github.io/osv-schema
type PackageVuln struct {
	osvschema.Vulnerability

	// The extracted package associated with this vuln.
	Package *extractor.Package
	// The plugins (e.g. Detectors, Enrichers) that found this vuln.
	Plugins []string
	// Signals that indicate this finding is not exploitable.
	ExploitabilitySignals []*vex.FindingExploitabilitySignal
}

// GenericFinding is used to describe generic security findings not associated with any
// specific package, e.g. weak credentials.
// Note: If you need to store more structured data related to a vulnerability, consider
// introducing a new vulnerability type instead of using GenericFinding.
type GenericFinding struct {
	// Info specific to the vuln. Should always be the same for the same type of vuln.
	Adv *GenericFindingAdvisory
	// Instance-specific info such as location of the vulnerable files.
	Target *GenericFindingTargetDetails
	// The plugins (e.g. Detectors, Enrichers) that found this vuln.
	Plugins []string
	// Signals that indicate this finding is not exploitable.
	ExploitabilitySignals []*vex.FindingExploitabilitySignal
}

// GenericFindingAdvisory describes a security finding and how to remediate it. It should not
// contain any information specific to the target (e.g. which files were found vulnerable).
type GenericFindingAdvisory struct {
	// A unique ID for the finding.
	ID *AdvisoryID
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
	Sev            SeverityEnum
}

// AdvisoryID is a unique identifier per advisory.
type AdvisoryID struct {
	Publisher string // e.g. "CVE".
	Reference string // e.g. "CVE-2023-1234".
}

// SeverityEnum is an enum-based representation of the finding's severity.
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

// GenericFindingTargetDetails contains instance-specific details about
// the generic security finding.
type GenericFindingTargetDetails struct {
	// Free-text info.
	Extra string
}

// LINT.ThenChange(/binary/proto/scan_result.proto)

// PackageToAffected creates an osvschema.Affected struct from the given
// Package, fixed ecosystem version, and severity.
func PackageToAffected(pkg *extractor.Package, fixed string, severity *osvschema.Severity) []osvschema.Affected {
	return []osvschema.Affected{{
		Package: osvschema.Package{
			Ecosystem: pkg.Ecosystem().String(),
			Name:      pkg.Name,
		},
		Severity: []osvschema.Severity{*severity},
		Ranges: []osvschema.Range{{
			Type:   osvschema.RangeEcosystem,
			Events: []osvschema.Event{{Fixed: fixed}},
		}},
	}}
}
