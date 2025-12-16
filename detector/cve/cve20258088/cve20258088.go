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

// Package cve20258088 implements a SCALIBR Detector for CVE-2025-8088
package cve20258088

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/semantic"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// Precompiled regex pattern for matching WinRAR product names with word boundaries
var (
	winrarNameRegex = regexp.MustCompile(`(?i)\b(winrar|unrar)\b|\brar\b`)
)

const (
	// Name of the detector.
	Name = "cve/cve-2025-8088"
)

// Detector is a SCALIBR Detector for CVE-2025-8088.
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
	return &plugin.Capabilities{OS: plugin.OSWindows, DirectFS: true, RunningSystem: true}
}

// RequiredExtractors of the detector.
func (Detector) RequiredExtractors() []string {
	return []string{"windows/ospackages", "os/peversion"}
}

// DetectedFinding returns generic vulnerability information about what is detected.
func (d Detector) DetectedFinding() inventory.Finding {
	return d.findingForPackage(nil)
}

func (d Detector) findingForPackage(dbSpecific map[string]any) inventory.Finding {
	pkg := &extractor.Package{
		Name:     "winrar",
		PURLType: "generic",
	}
	vuln := d.makePackageVulnWithDb(pkg, "7.13", "WinRAR path traversal vulnerability (<7.13)",
		"WinRAR versions before 7.13 are vulnerable to a path traversal attack that allows attackers to extract files to arbitrary locations outside the intended extraction directory.",
		dbSpecific)
	return inventory.Finding{PackageVulns: []*inventory.PackageVuln{vuln}}
}

// Scan checks for the presence of the WinRAR RCE CVE-2025-8088 vulnerability.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	var findings []*inventory.PackageVuln

	// === Phase 1: Installed packages via package index ===
	if px == nil {
		log.Infof("cve20258088: PackageIndex is nil, no packages to scan")
		return inventory.Finding{}, nil
	}

	allPackages := px.GetAll()
	log.Infof("cve20258088: Scanning %d packages from PackageIndex", len(allPackages))

	for _, pkg := range allPackages {
		log.Debugf("cve20258088: Checking package %q version %q", pkg.Name, pkg.Version)

		// Use word boundary regex to avoid false positives like "Libraries", "Hardware", etc.
		if !winrarNameRegex.MatchString(pkg.Name) {
			continue
		}

		log.Debugf("cve20258088: Package %q matched WinRAR regex", pkg.Name)

		normalizedVersion := normalizeVersion(pkg.Version)
		if normalizedVersion == "" {
			continue
		}

		if sv, err := semantic.Parse(normalizedVersion, "Maven"); err == nil {
			if cmp, err := sv.CompareStr("7.13"); err == nil && cmp < 0 {
				log.Infof("cve20258088: Vulnerable WinRAR package found: Package %q, Version: %q",
					pkg.Name, normalizedVersion)

				dbSpecific := map[string]any{
					"extra": fmt.Sprintf("%s %s %s", pkg.Name, normalizedVersion, strings.Join(pkg.Locations, ", ")),
				}
				finding := d.findingForPackage(dbSpecific)
				findings = append(findings, finding.PackageVulns...)
			}
		}
	}

	if len(findings) == 0 {
		return inventory.Finding{}, nil
	}
	return inventory.Finding{PackageVulns: findings}, nil
}

// makePackageVulnWithDb constructs a PackageVuln for CVE-2025-8088 with custom DatabaseSpecific.
func (Detector) makePackageVulnWithDb(pkg *extractor.Package, normalizedVersion, summary, details string, dbSpecific map[string]any) *inventory.PackageVuln {
	vuln := &inventory.PackageVuln{
		Package: pkg,
		Vulnerability: osvschema.Vulnerability{
			ID:      "CVE-2025-8088",
			Summary: summary,
			Details: details,
			Affected: inventory.PackageToAffected(pkg, "7.13", &osvschema.Severity{
				Type:  osvschema.SeverityCVSSV3,
				Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
			}),
			DatabaseSpecific: dbSpecific,
		},
	}

	return vuln
}

// normalizeVersion tries to standardize version strings
func normalizeVersion(ver string) string {
	ver = strings.TrimSpace(ver)
	ver = strings.ReplaceAll(ver, "_", ".")
	ver = strings.ReplaceAll(ver, "-", ".")
	return ver
}
