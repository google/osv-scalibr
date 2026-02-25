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

	// chromiumBackportCoreFloor is the minimum Chromium core version that includes
	// a backported CVE-2025-5419 fix, first shipped in Electron 34.5.8.
	// This value applies only when evaluating an Electron app's embedded Chromium
	// core — it MUST NOT be used for standalone Chrome or Chromium packages, which
	// have no such backport branch and are only fixed at 137.0.7151.68.
	chromiumBackportCoreFloor = "132.0.6834.210"

	edgeFixed136 = "136.0.3240.115"
	edgeFixed137 = "137.0.3296.62"
)

var (
	// electronFixedByMajor maps each supported Electron major to the first
	// release in that branch that carries a backported CVE-2025-5419 fix.
	electronFixedByMajor = map[int]string{
		34: "34.5.8",
		35: "35.5.1",
		36: "36.4.0",
		37: "37.0.0-beta.3",
	}

	electronSemverPattern  = regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	electronNumericPattern = regexp.MustCompile(`^\d+\.\d+\.\d+(?:\.\d+)?$`)
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

// isVulnerable compares two 4-part Chromium-style versions ("MAJOR.MINOR.BUILD.PATCH").
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

// fixedVersionForEdge returns the fixed Edge version for the installed major.
// C5: merged the previously redundant "v[0] < 136" and "v[0] == 136" cases.
func fixedVersionForEdge(evaluatedVersion string) (string, bool, error) {
	v, err := parseVersion(evaluatedVersion)
	if err != nil {
		return "", false, err
	}
	switch {
	case v[0] <= 136:
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
		// C1: standalone Chrome has no backport branches. Always compare
		// against chromeFixed (137.0.7151.68) directly.
		return evaluateStandaloneChromiumPolicy(pkg.Version, chromeFixed)
	case "chromium":
		// C1: same as google-chrome — no backport floor applies.
		return evaluateStandaloneChromiumPolicy(pkg.Version, chromiumFixed)
	case "microsoft-edge":
		fixedVersion, shouldCheck, err := fixedVersionForEdge(pkg.Version)
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

// evaluateStandaloneChromiumPolicy evaluates a standalone Chrome or Chromium
// package directly against the upstream fixed version. Unlike Electron-embedded
// Chromium, standalone Chrome has no backport branches for this CVE.
func evaluateStandaloneChromiumPolicy(version, fixedVersion string) (policyDecision, bool, error) {
	return policyDecision{
		evaluatedVersion: version,
		fixedVersion:     fixedVersion,
		compare:          isVulnerable,
		extra:            fmt.Sprintf("evaluated core %s", version),
	}, true, nil
}

func evaluateElectronPolicy(pkg *extractor.Package) (policyDecision, bool, error) {
	md, ok := pkg.Metadata.(*chromiumapps.Metadata)
	if !ok || md == nil {
		return policyDecision{}, false, nil
	}

	if md.ElectronVersion != "" {
		fixedVersion, shouldCheck, err := electronFixedVersionForBackport(md.ElectronVersion)
		if err == nil && shouldCheck {
			major, _ := electronMajorFromVersion(md.ElectronVersion)
			extra := fmt.Sprintf("evaluated electron %s, core %s", md.ElectronVersion, md.ChromiumVersion)
			if major < 34 {
				// C4: EOL Electron branches have no in-branch fix. The comparison
				// value "34.5.8" only flags the version as vulnerable; it is NOT
				// achievable as a same-major patch. Users must upgrade to Electron 34+.
				extra += "; EOL branch, no in-branch fix available, must upgrade to Electron 34+"
			}
			return policyDecision{
				evaluatedVersion: md.ElectronVersion,
				fixedVersion:     fixedVersion,
				compare:          isElectronVulnerable,
				extra:            extra,
			}, true, nil
		}
	}

	if md.ChromiumVersion == "" {
		return policyDecision{}, false, nil
	}

	return evaluateElectronChromiumCorePolicy(md.ChromiumVersion, electronCoreFixed)
}

// evaluateElectronChromiumCorePolicy evaluates the Chromium core version
// embedded in an Electron application. It applies chromiumBackportCoreFloor
// (132.0.6834.210, first backported in Electron 34.5.8) as a lower bound,
// enabling detection of Electron apps whose embedded Chromium predates even
// the earliest backport. This function must NOT be used for standalone Chrome.
func evaluateElectronChromiumCorePolicy(installedVersion, fixedVersion string) (policyDecision, bool, error) {
	belowBackportFloor, err := isVulnerable(installedVersion, chromiumBackportCoreFloor)
	if err != nil {
		return policyDecision{}, false, err
	}
	if belowBackportFloor {
		return policyDecision{
			evaluatedVersion: installedVersion,
			fixedVersion:     chromiumBackportCoreFloor,
			compare:          isVulnerable,
			extra:            fmt.Sprintf("evaluated core %s (below Electron backport floor %s)", installedVersion, chromiumBackportCoreFloor),
		}, true, nil
	}
	return policyDecision{
		evaluatedVersion: installedVersion,
		fixedVersion:     fixedVersion,
		compare:          isVulnerable,
		extra:            fmt.Sprintf("evaluated core %s", installedVersion),
	}, true, nil
}

// electronFixedVersionForBackport returns the first patched Electron release
// for the major of the given version string.
func electronFixedVersionForBackport(version string) (string, bool, error) {
	major, err := electronMajorFromVersion(version)
	if err != nil {
		return "", false, err
	}
	if major < 34 {
		// EOL branches: no in-branch backport exists. "34.5.8" is the earliest
		// known patched Electron release (a different major) and is used only
		// to produce a vulnerability finding. The extra field in the calling
		// policyDecision must note the EOL status explicitly.
		return "34.5.8", true, nil
	}
	fixedVersion, ok := electronFixedByMajor[major]
	if !ok {
		// Unknown future majors: fall back to the upstream Chromium core check.
		return "", false, nil
	}
	return fixedVersion, true, nil
}

func electronMajorFromVersion(version string) (int, error) {
	if numeric, ok := parseElectronNumericVersion(version); ok {
		return numeric[0], nil
	}
	normalized, err := normalizeElectronForCompare(version)
	if err != nil {
		return 0, err
	}
	return electronMajor(normalized)
}

// isElectronVulnerable compares two Electron version strings using semver.
// C3: replaced the previous dual numeric/semver path with a single semver
// path via normalizeElectronForCompare. The old numeric fast-path caused an
// error when the installed version was a plain stable string (e.g. "37.0.0")
// but the fixed version carried a pre-release tag (e.g. "37.0.0-beta.3"),
// which resulted in the package being silently skipped instead of being
// correctly evaluated as not-vulnerable (stable > any pre-release in semver).
func isElectronVulnerable(version, fixedVersion string) (bool, error) {
	normInstalled, err := normalizeElectronForCompare(version)
	if err != nil {
		return false, err
	}
	normFixed, err := normalizeElectronForCompare(fixedVersion)
	if err != nil {
		return false, err
	}
	return semver.Compare(normInstalled, normFixed) < 0, nil
}

// normalizeElectronForCompare converts an Electron version string into a
// canonical "vMAJOR.MINOR.PATCH[-pre]" semver string suitable for comparison.
// Four-part numeric versions (e.g. "36.4.0.1") have their fourth segment
// stripped (producing "v36.4.0") so that semver.Compare treats them as equal
// to or later than the three-part release ("36.4.0 >= 36.4.0" → not vulnerable).
// Pre-release labels are preserved unchanged (e.g. "37.0.0-beta.3").
func normalizeElectronForCompare(version string) (string, error) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(version, "v"))
	if trimmed == "" {
		return "", fmt.Errorf("invalid electron version %q", version)
	}
	// Four-part pure-numeric versions: strip the fourth segment.
	if electronNumericPattern.MatchString(trimmed) {
		parts := strings.Split(trimmed, ".")
		if len(parts) == 4 {
			trimmed = strings.Join(parts[:3], ".")
		}
	}
	if !electronSemverPattern.MatchString(trimmed) {
		return "", fmt.Errorf("invalid electron version %q", version)
	}
	return "v" + trimmed, nil
}

func parseElectronNumericVersion(version string) ([]int, bool) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(version, "v"))
	if !electronNumericPattern.MatchString(trimmed) {
		return nil, false
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) < 3 || len(parts) > 4 {
		return nil, false
	}

	nums := make([]int, 0, 4)
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		nums = append(nums, n)
	}
	for len(nums) < 4 {
		nums = append(nums, 0)
	}
	return nums, true
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
