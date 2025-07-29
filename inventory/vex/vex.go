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

// Package vex stores data structures used to represent exploitability signals in SCALIBR scan results.
package vex

import "slices"

// PackageExploitabilitySignal is used to indicate that specific vulnerabilities
// are not applicable to a given package.
type PackageExploitabilitySignal struct {
	// The name of the plugin (e.g. Annotator) that added this signal.
	Plugin string
	// Reason for exclusion.
	Justification Justification
	// Advisory Identifier (CVE, GHSA, ...) and aliases of the vulns that are not
	// applicable to this package.
	VulnIdentifiers []string
	// Indicates that all vulnerabilities associated with the package are irrelevant.
	// VulnIdentifiers should be empty when this is set to true.
	MatchesAllVulns bool
}

// FindingExploitabilitySignal is used to indicate that a finding is not exploitable.
type FindingExploitabilitySignal struct {
	// The name of the plugin (e.g. Annotator) that added this signal.
	Plugin string
	// Reason for exclusion.
	Justification Justification
}

// Justification enumerates various vuln exclusion reasons.
// It mirrors the format from the official VEX documentation
// (https://www.cisa.gov/sites/default/files/publications/VEX_Status_Justification_Jun22.pdf)
type Justification int64

const (
	// Unspecified indicated the exclusion reason has not been specified.
	Unspecified Justification = iota
	// ComponentNotPresent indicates the vulnerable component is not used in the
	// affected artifact.
	ComponentNotPresent
	// VulnerableCodeNotPresent indicates the component is used but vulnerable
	// code was removed or not included.
	VulnerableCodeNotPresent
	// VulnerableCodeNotInExecutePath indicates the vulnerable code is included
	// but is not executed.
	VulnerableCodeNotInExecutePath
	// VulnerableCodeCannotBeControlledByAdversary indicates the vulnerable code
	// is executed but can't be exploited due to program logic.
	VulnerableCodeCannotBeControlledByAdversary
	// InlineMitigationAlreadyExists indicates the vulnerable code can be
	// executed but additional mitigations prevent exploitation.
	InlineMitigationAlreadyExists
)

// FindingVEXFromPackageVEX converts package VEXes to finding VEXes if they're
// applicable to a finding with the given ID.
func FindingVEXFromPackageVEX(vulnID string, pkgVEXes []*PackageExploitabilitySignal) []*FindingExploitabilitySignal {
	var result []*FindingExploitabilitySignal
	for _, pkgVEX := range pkgVEXes {
		if pkgVEX.MatchesAllVulns || slices.Contains(pkgVEX.VulnIdentifiers, vulnID) {
			result = append(result, &FindingExploitabilitySignal{
				Plugin:        pkgVEX.Plugin,
				Justification: pkgVEX.Justification,
			})
		}
	}
	return result
}
