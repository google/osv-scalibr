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

// Package cve20255419 implements a SCALIBR detector for CVE-2025-5419.
package cve20255419

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/misc/chromiumapps"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/mod/semver"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

const (
	// Name is the unique name of this detector.
	Name = "cve/cve-2025-5419"
)

const (
	chromeFixed       = "137.0.7151.68"
	chromiumFixed     = "137.0.7151.68"
	electronCoreFixed = "137.0.7151.68"

	edgeFixed136 = "136.0.3240.115"
	edgeFixed137 = "137.0.3296.62"
)

var (
	electronFixedByMajor = map[int]string{
		34: "34.5.8",
		35: "35.5.1",
		36: "36.4.0",
		37: "37.0.0-beta.3",
	}

	electronVersionPattern = regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
)

// Detector checks Chromium-family package versions for CVE-2025-5419.
type Detector struct{}

type compareFunc func(installed, fixed string) (bool, error)

type policyDecision struct {
	evaluatedVersion string
	fixedVersion     string
	compare          compareFunc
	extra            string
}

// New returns a CVE-2025-5419 detector.
func New(cfg *cpb.PluginConfig) (detector.Detector, error) {
	return &Detector{}, nil
}

// Name returns the detector name.
func (Detector) Name() string { return Name }

// Version returns the detector implementation version.
func (Detector) Version() int { return 0 }

// Requirements returns detector requirements.
func (Detector) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// RequiredExtractors returns extractor dependencies.
func (Detector) RequiredExtractors() []string {
	return []string{chromiumapps.Name}
}

// DetectedFinding returns generic vulnerability metadata.
func (d Detector) DetectedFinding() inventory.Finding {
	return inventory.Finding{PackageVulns: []*inventory.PackageVuln{
		d.findingForPackage("chromium", chromiumFixed, nil, nil),
	}}
}

// Scan identifies packages affected by CVE-2025-5419.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	if ctx.Err() != nil {
		return inventory.Finding{}, ctx.Err()
	}
	if px == nil {
		return inventory.Finding{}, nil
	}

	var findings []*inventory.PackageVuln
	for _, pkg := range px.GetAll() {
		if ctx.Err() != nil {
			return inventory.Finding{}, ctx.Err()
		}
		pkgName := strings.ToLower(pkg.Name)
		decision, shouldCheck, err := evaluatePackagePolicy(pkgName, pkg)
		if err != nil {
			continue
		}
		if !shouldCheck {
			continue
		}

		vulnerable, err := decision.compare(decision.evaluatedVersion, decision.fixedVersion)
		if err != nil || !vulnerable {
			continue
		}

		dbSpecific, err := structpb.NewStruct(map[string]any{
			"extra": fmt.Sprintf("%s %s (%s) at %s", pkg.Name, pkg.Version, decision.extra, strings.Join(pkg.Locations, ", ")),
		})
		if err != nil {
			return inventory.Finding{}, fmt.Errorf("failed creating dbSpecific struct: %w", err)
		}
		findings = append(findings, d.findingForPackage(pkg.Name, decision.fixedVersion, dbSpecific, pkg))
	}
	return inventory.Finding{PackageVulns: findings}, nil
}

func (Detector) findingForPackage(pkgName, fixedVersion string, dbSpecific *structpb.Struct, pkg *extractor.Package) *inventory.PackageVuln {
	p := &extractor.Package{
		Name:     pkgName,
		PURLType: "generic",
	}
	return &inventory.PackageVuln{
		Package: pkg,
		Vulnerability: &osvpb.Vulnerability{
			Id:      "CVE-2025-5419",
			Summary: "Out-of-bounds read and write in V8 in Chromium-based browsers",
			Details: "Out-of-bounds read and write in V8 in Google Chrome prior to 137.0.7151.68 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.",
			Affected: inventory.PackageToAffected(p, fixedVersion, &osvpb.Severity{
				Type:  osvpb.Severity_CVSS_V3,
				Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
			}),
			DatabaseSpecific: dbSpecific,
		},
	}
}

func isVulnerable(version string, fixed string) (bool, error) {
	installed, err := parseVersion(version)
	if err != nil {
		return false, err
	}
	fixedVer, err := parseVersion(fixed)
	if err != nil {
		return false, err
	}
	return compareVersion(installed, fixedVer) < 0, nil
}

func parseVersion(version string) ([4]int, error) {
	var parsed [4]int
	parts := strings.Split(strings.TrimSpace(version), ".")
	if len(parts) != 4 {
		return parsed, fmt.Errorf("invalid version %q", version)
	}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			return parsed, fmt.Errorf("invalid version %q: %w", version, err)
		}
		parsed[i] = n
	}
	return parsed, nil
}

func compareVersion(a, b [4]int) int {
	for i := 0; i < 4; i++ {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

func fixedVersionForPackage(pkgName string, evaluatedVersion string) (string, bool, error) {
	if pkgName != "microsoft-edge" {
		return "", false, nil
	}

	v, err := parseVersion(evaluatedVersion)
	if err != nil {
		return "", false, err
	}
	switch {
	case v[0] < 136:
		return edgeFixed136, true, nil
	case v[0] == 136:
		return edgeFixed136, true, nil
	case v[0] == 137:
		return edgeFixed137, true, nil
	default:
		// Newer major versions are considered already fixed for this CVE.
		return "", false, nil
	}
}

func evaluatePackagePolicy(pkgName string, pkg *extractor.Package) (policyDecision, bool, error) {
	switch pkgName {
	case "google-chrome":
		return policyDecision{
			evaluatedVersion: pkg.Version,
			fixedVersion:     chromeFixed,
			compare:          isVulnerable,
			extra:            fmt.Sprintf("evaluated core %s", pkg.Version),
		}, true, nil
	case "chromium":
		return policyDecision{
			evaluatedVersion: pkg.Version,
			fixedVersion:     chromiumFixed,
			compare:          isVulnerable,
			extra:            fmt.Sprintf("evaluated core %s", pkg.Version),
		}, true, nil
	case "microsoft-edge":
		fixedVersion, shouldCheck, err := fixedVersionForPackage(pkgName, pkg.Version)
		if err != nil || !shouldCheck {
			return policyDecision{}, shouldCheck, err
		}
		return policyDecision{
			evaluatedVersion: pkg.Version,
			fixedVersion:     fixedVersion,
			compare:          isVulnerable,
			extra:            fmt.Sprintf("evaluated core %s", pkg.Version),
		}, true, nil
	case "electron":
		return evaluateElectronPolicy(pkg)
	default:
		return policyDecision{}, false, nil
	}
}

func evaluateElectronPolicy(pkg *extractor.Package) (policyDecision, bool, error) {
	md, ok := pkg.Metadata.(*chromiumapps.Metadata)
	if !ok || md == nil || md.ChromiumVersion == "" {
		// Preserve behavior: skip Electron when Chromium core was not extracted.
		return policyDecision{}, false, nil
	}

	if md.ElectronVersion != "" {
		fixedVersion, shouldCheck, err := electronFixedVersionForBackport(md.ElectronVersion)
		if err == nil && shouldCheck {
			return policyDecision{
				evaluatedVersion: md.ElectronVersion,
				fixedVersion:     fixedVersion,
				compare:          isElectronVulnerable,
				extra:            fmt.Sprintf("evaluated electron %s, core %s", md.ElectronVersion, md.ChromiumVersion),
			}, true, nil
		}
	}

	return policyDecision{
		evaluatedVersion: md.ChromiumVersion,
		fixedVersion:     electronCoreFixed,
		compare:          isVulnerable,
		extra:            fmt.Sprintf("evaluated core %s", md.ChromiumVersion),
	}, true, nil
}

func electronFixedVersionForBackport(version string) (string, bool, error) {
	normalized, err := normalizeElectronVersion(version)
	if err != nil {
		return "", false, err
	}
	major, err := electronMajor(normalized)
	if err != nil {
		return "", false, err
	}
	fixedVersion, ok := electronFixedByMajor[major]
	if !ok {
		return "", false, nil
	}
	return fixedVersion, true, nil
}

func isElectronVulnerable(version, fixedVersion string) (bool, error) {
	normalizedInstalled, err := normalizeElectronVersion(version)
	if err != nil {
		return false, err
	}
	normalizedFixed, err := normalizeElectronVersion(fixedVersion)
	if err != nil {
		return false, err
	}
	return semver.Compare(normalizedInstalled, normalizedFixed) < 0, nil
}

func normalizeElectronVersion(version string) (string, error) {
	trimmed := strings.TrimSpace(version)
	if trimmed == "" {
		return "", fmt.Errorf("invalid electron version %q", version)
	}
	if !electronVersionPattern.MatchString(trimmed) {
		return "", fmt.Errorf("invalid electron version %q", version)
	}
	if strings.HasPrefix(trimmed, "v") {
		return trimmed, nil
	}
	return "v" + trimmed, nil
}

func electronMajor(semVersion string) (int, error) {
	major := strings.TrimPrefix(semver.Major(semVersion), "v")
	if major == "" {
		return 0, fmt.Errorf("invalid electron semver %q", semVersion)
	}
	n, err := strconv.Atoi(major)
	if err != nil {
		return 0, fmt.Errorf("invalid electron major %q: %w", semVersion, err)
	}
	return n, nil
}
