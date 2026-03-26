// Copyright 2026 Google LLC
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

// Package canisterworm implements a detector that checks for specific malicious NPM packages.
package canisterworm

import (
	"context"
	"fmt"
	"slices"

	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this detector.
	Name = "cve/npm/canisterworm"
)

// Detector is a SCALIBR Detector that checks for specific malicious NPM packages.
type Detector struct{}

// New returns a detector.
func New(cfg *cpb.PluginConfig) (detector.Detector, error) {
	return &Detector{}, nil
}

// Name of the detector.
func (Detector) Name() string { return Name }

// Version of the detector.
func (Detector) Version() int { return 0 }

// Requirements of the detector.
func (Detector) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// RequiredExtractors returns the NPM-related extractors.
func (Detector) RequiredExtractors() []string {
	return []string{
		"javascript/packagejson",
		"javascript/packagelockjson",
		"javascript/yarnlock",
		"javascript/pnpmlock",
	}
}

var maliciousPackages = map[string][]string{
	"@airtm/uuid-base32":                  {"1.0.2"},
	"@emilgroup/account-sdk-node":         {"1.40.2", "1.40.1"},
	"@emilgroup/account-sdk":              {"1.41.2", "1.41.1"},
	"@emilgroup/accounting-sdk-node":      {"1.26.2", "1.26.1"},
	"@emilgroup/accounting-sdk":           {"1.27.3", "1.27.2", "1.27.1"},
	"@emilgroup/api-documentation":        {"1.19.2", "1.19.1"},
	"@emilgroup/auth-sdk-node":            {"1.21.2", "1.21.1"},
	"@emilgroup/auth-sdk":                 {"1.25.2", "1.25.1"},
	"@emilgroup/billing-sdk-node":         {"1.57.2", "1.57.1"},
	"@emilgroup/billing-sdk":              {"1.56.2", "1.56.1"},
	"@emilgroup/changelog-sdk-node":       {"1.0.3", "1.0.2"},
	"@emilgroup/claim-sdk-node":           {"1.39.2", "1.39.1"},
	"@emilgroup/claim-sdk":                {"1.41.2", "1.41.1"},
	"@emilgroup/commission-sdk-node":      {"1.0.3", "1.0.2", "1.0.1"},
	"@emilgroup/commission-sdk":           {"1.0.3", "1.0.2", "1.0.1"},
	"@emilgroup/customer-sdk-node":        {"1.55.2", "1.55.1"},
	"@emilgroup/customer-sdk":             {"1.54.5", "1.54.4", "1.54.3", "1.54.2", "1.54.1"},
	"@emilgroup/discount-sdk-node":        {"1.5.2", "1.5.1"},
	"@emilgroup/discount-sdk":             {"1.5.3", "1.5.2", "1.5.1"},
	"@emilgroup/document-sdk-node":        {"1.43.6", "1.43.5", "1.43.4", "1.43.3", "1.43.2", "1.43.1"},
	"@emilgroup/document-sdk":             {"1.45.2", "1.45.1"},
	"@emilgroup/document-uploader":        {"0.0.12", "0.0.11", "0.0.10"},
	"@emilgroup/docxtemplater-util":       {"1.1.4", "1.1.3", "1.1.2"},
	"@emilgroup/gdv-sdk-node":             {"2.6.3", "2.6.2", "2.6.1"},
	"@emilgroup/gdv-sdk":                  {"2.6.2", "2.6.1"},
	"@emilgroup/insurance-sdk-node":       {"1.95.2", "1.95.1"},
	"@emilgroup/insurance-sdk":            {"1.97.6", "1.97.5", "1.97.4", "1.97.3", "1.97.2", "1.97.1"},
	"@emilgroup/notification-sdk-node":    {"1.4.2", "1.4.1"},
	"@emilgroup/numbergenerator-sdk-node": {"1.3.3", "1.3.2", "1.3.1"},
	"@emilgroup/partner-portal-sdk-node":  {"1.1.2", "1.1.1"},
	"@emilgroup/partner-portal-sdk":       {"1.1.3", "1.1.2", "1.1.1"},
	"@emilgroup/partner-sdk-node":         {"1.19.2", "1.19.1"},
	"@emilgroup/partner-sdk":              {"1.19.3", "1.19.2", "1.19.1"},
	"@emilgroup/payment-sdk-node":         {"1.23.2", "1.23.1"},
	"@emilgroup/payment-sdk":              {"1.15.2", "1.15.1"},
	"@emilgroup/process-manager-sdk-node": {"1.13.2", "1.13.1"},
	"@emilgroup/process-manager-sdk":      {"1.4.2", "1.4.1"},
	"@emilgroup/public-api-sdk-node":      {"1.35.2", "1.35.1"},
	"@emilgroup/public-api-sdk":           {"1.33.2", "1.33.1"},
	"@emilgroup/setting-sdk-node":         {"0.2.3", "0.2.2", "0.2.1"},
	"@emilgroup/setting-sdk":              {"0.2.3", "0.2.2", "0.2.1"},
	"@emilgroup/task-sdk-node":            {"1.0.4", "1.0.3", "1.0.2"},
	"@emilgroup/task-sdk":                 {"1.0.4", "1.0.3", "1.0.2"},
	"@emilgroup/tenant-sdk-node":          {"1.33.2", "1.33.1"},
	"@emilgroup/tenant-sdk":               {"1.34.2", "1.34.1"},
	"@emilgroup/translation-sdk-node":     {"1.1.2", "1.1.1"},
	"@leafnoise/mirage":                   {"2.0.3"},
	"@opengov/form-builder":               {"0.12.3"},
	"@opengov/form-renderer":              {"0.2.20"},
	"@opengov/form-utils":                 {"0.7.2"},
	"@opengov/ppf-backend-types":          {"1.141.2"},
	"@opengov/ppf-eslint-config":          {"0.1.11"},
	"@opengov/qa-record-types-api":        {"1.0.3"},
	"@pypestream/floating-ui-dom":         {"2.15.1"},
	"@teale.io/eslint-config":             {"1.8.16", "1.8.15", "1.8.14", "1.8.13", "1.8.12", "1.8.11", "1.8.10", "1.8.9"},
	"@virtahealth/substrate-root":         {"1.0.1"},
	"babel-plugin-react-pure-component":   {"0.1.6"},
	"cit-playwright-tests":                {"1.0.1"},
	"eslint-config-ppf":                   {"0.128.2"},
	"eslint-config-service-users":         {"0.0.3"},
	"jest-preset-ppf":                     {"0.0.2"},
	"opengov-k6-core":                     {"1.0.2"},
	"react-autolink-text":                 {"2.0.1"},
	"react-leaflet-cluster-layer":         {"0.0.4"},
	"react-leaflet-heatmap-layer":         {"2.0.1"},
	"react-leaflet-marker-layer":          {"0.1.5"},
}

// DetectedFinding returns generic vulnerability information about what is detected.
func (d Detector) DetectedFinding() inventory.Finding {
	return inventory.Finding{
		GenericFindings: []*inventory.GenericFinding{
			&inventory.GenericFinding{
				Adv: d.vulnerability(),
			},
		},
	}
}

// Scan checks for the presence of the malicious NPM packages.
func (d Detector) Scan(ctx context.Context, scanRoot *fs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	result := inventory.Finding{}
	if px == nil {
		return result, nil
	}

	for _, pkg := range px.GetAllOfType(purl.TypeNPM) {
		if versions, ok := maliciousPackages[pkg.Name]; ok {
			if slices.Contains(versions, pkg.Version) {
				result.GenericFindings = append(result.GenericFindings, d.findingForPackage(pkg.Name, pkg.Version))
			}
		}
	}

	return result, nil
}

func (d Detector) findingForPackage(pkgname, version string) *inventory.GenericFinding {
	unsafeVersions := maliciousPackages[pkgname]
	return &inventory.GenericFinding{
		Adv: d.vulnerability(),
		Target: &inventory.GenericFindingTargetDetails{
			Extra: fmt.Sprintf("Vulnerable packages: %s@%s [known UNSAFE versions: %v]", pkgname, version, unsafeVersions),
		},
	}
}

func (d Detector) vulnerability() *inventory.GenericFindingAdvisory {
	return &inventory.GenericFindingAdvisory{
		ID: &inventory.AdvisoryID{
			Publisher: "SCALIBR",
			Reference: "SUPPLYCHAIN_CANISTERWORM",
		},
		Title:          "Malicious version of package detected",
		Description:    "One or more NPM packages were identified as potentially compromised",
		Recommendation: "Remove the aforementioned packages. Escalate to a security team for further investigation. Update to a version that is known to be safe.",
		Sev:            inventory.SeverityCritical,
	}
}
