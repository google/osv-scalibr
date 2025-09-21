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
	"io/fs"
	"os"
	"path/filepath"
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
	"github.com/saferwall/pe"
)

// Precompiled regex patterns
var (
	peRegex   = regexp.MustCompile(`(?i)(winrar|rar|unrar).*?(\.exe|\.dll)$`)
	archRegex = regexp.MustCompile(`(?i)(x64|x86|arm64|arm32|portable)`)
	verRegex  = regexp.MustCompile(`(\d+[\._-]?\d*)`)
)

const (
	// Name of the detector.
	Name = "cve/cve-2025-8088"
)

// Options configures the detector behavior.
type Options struct {
	// DeepScan toggles the expensive full filesystem crawl.
	// Default (false): if true, perform the existing FS walk to catch renamed/portable binaries in non-standard paths.
	// False: reuse packages from extractor (dotnet/pe) without walking the FS.
	DeepScan bool
}

// Detector is a SCALIBR Detector for CVE-2025-8088.
type Detector struct {
	opts Options
}

// New returns a detector with options.
func New(opts Options) detector.Detector {
	return &Detector{opts: opts}
}

// NewDefault returns a detector with default options (DeepScan enabled).
func NewDefault() detector.Detector {
	return &Detector{
		opts: Options{
			DeepScan: false,
		},
	}
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
	return []string{"windows/ospackages"}
}

// DetectedFinding returns generic vulnerability information about what is detected.
func (Detector) DetectedFinding() inventory.Finding {
	return inventory.Finding{PackageVulns: []*inventory.PackageVuln{{
		Vulnerability: osvschema.Vulnerability{
			ID:      "CVE-2025-8088",
			Summary: "WinRAR path traversal vulnerability (<7.13)",
			Details: "Detects WinRAR installs or portables < 7.13, using robust and reliable PE analysis (if DeepScan enabled)",
		},
	}}}
}

// Scan checks for the presence of the WinRAR RCE CVE-2025-8088 vulnerability.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	var findings []*inventory.PackageVuln

	// === Phase 1: Installed packages via package index ===
	if px != nil {
		for _, pkg := range px.GetAll() {
			nameLower := strings.ToLower(pkg.Name)
			if strings.Contains(nameLower, "winrar") {
				normalizedVersion := normalizeVersion(pkg.Version)

				if sv, err := semantic.Parse(normalizedVersion, "Go"); err == nil {
					if cmp, err := sv.CompareStr("7.13"); err == nil && cmp < 0 {
						log.Infof("cve20258088: Vulnerable WinRAR package installation found (uninstall them): Package %s, Version: %s", pkg.Name, normalizedVersion)

						details := fmt.Sprintf("Installed WinRAR %s detected via package index", normalizedVersion)
						vuln := d.makePackageVuln(pkg, normalizedVersion, "WinRAR vulnerable version detected (installed package)", details)
						findings = append(findings, vuln)
					}
				}
			}
		}
	}

	// === Phase 2: Hybrid ===
	if !d.opts.DeepScan {
		// Lightweight: reuse packages produced by extractors (any extractor)
		// No filesystem walk, no re-parsing binaries.
		if px != nil {
			for _, pkg := range px.GetAll() {
				// Identify WinRAR family by name across any extractor's packages
				nameLower := strings.ToLower(pkg.Name)
				if !(strings.Contains(nameLower, "winrar") || strings.Contains(nameLower, "unrar") || strings.Contains(nameLower, "rar")) {
					continue
				}

				nver := normalizeVersion(pkg.Version)
				if nver == "" {
					// If extractor didn't get a version, skip in lightweight mode.
					// (DeepScan can still catch it via PE/resource parsing.)
					continue
				}

				if sv, err := semantic.Parse(nver, "Go"); err == nil {
					if cmp, err := sv.CompareStr("7.13"); err == nil && cmp < 0 {
						details := fmt.Sprintf("%s from extractor (PURLType=%s), version: %s", pkg.Name, pkg.PURLType, nver)
						vuln := d.makePackageVuln(pkg, nver, "WinRAR vulnerable version detected (extracted binary)", details)
						findings = append(findings, vuln)
					}
				}
			}
		} else {
			log.Debugf("cve20258088: Package index is null %s", px)
		}
	} else {
		rootInfo, err := os.Stat(scanRoot.Path)
		if err != nil || !rootInfo.IsDir() {
			log.Warnf("cve20258088: Root path invalid or inaccessible: %s, skipping deepscan", scanRoot.Path)
		} else {
			err := filepath.WalkDir(scanRoot.Path, func(path string, de fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					log.Warnf("cve20258088: Walk error for %s: %v", path, walkErr)
					return nil
				}
				if de == nil || de.IsDir() {
					return nil
				}
				ext := strings.ToLower(filepath.Ext(de.Name()))
				if ext != ".exe" && ext != ".dll" {
					return nil
				}

				confidence := 0
				var component string

				// Indicator 1: Filename match
				if peRegex.MatchString(de.Name()) {
					confidence += 2
					matches := peRegex.FindStringSubmatch(de.Name())
					if len(matches) > 1 {
						component = matches[1]
					}
				}

				// Indicator 2: PE resource analysis - extract version info from PE resources
				// Now check PE resources for ALL .exe/.dll files, not just regex matches
				binVersion, prodName := extractPEVersion(path)
				if prodName != "" {
					prodNameLower := strings.ToLower(prodName)
					if strings.Contains(prodNameLower, "winrar") || strings.Contains(prodNameLower, "rar") || strings.Contains(prodNameLower, "unrar") {
						confidence += 2
						if component == "" {
							component = prodName
						}
					}
				}

				// Only report if confidence is high enough
				if confidence >= 2 && binVersion != "" {
					normalizedVersion := normalizeVersion(binVersion)

					if sv, err := semantic.Parse(normalizedVersion, "Go"); err == nil {
						if cmp, err := sv.CompareStr("7.13"); err == nil && cmp < 0 {
							log.Infof("cve20258088: Vulnerable WinRAR package found (delete them): %s, Package: %s, Version: %s", path, prodName, normalizedVersion)
							pkg := &extractor.Package{
								Name:         component,
								Version:      normalizedVersion,
								PURLType:     "generic",
								Locations:    []string{path},
								SourceCode:   &extractor.SourceCodeIdentifier{},
								LayerDetails: &extractor.LayerDetails{},
								Metadata:     nil,
							}

							details := fmt.Sprintf("%s found at %s, version: %s (confidence: %d)", component, path, normalizedVersion, confidence)
							vuln := d.makePackageVuln(pkg, normalizedVersion, "WinRAR vulnerable version detected", details)
							findings = append(findings, vuln)
						}
					}
				}
				return nil
			})
			if err != nil {
				log.Infof("cve20258088: WalkDir error: %v", err)
				return inventory.Finding{}, err
			}
		}
	}

	if len(findings) == 0 {
		return inventory.Finding{}, nil
	}
	return inventory.Finding{PackageVulns: findings}, nil
}

// makePackageVuln constructs a PackageVuln for CVE-2025-8088.
// normalizedVersion should be the already-normalized version string (e.g. "6.10").
func (Detector) makePackageVuln(pkg *extractor.Package, normalizedVersion, summary, details string) *inventory.PackageVuln {
	affected := []osvschema.Affected{{
		Package: osvschema.Package{
			Name:      pkg.Name,
			Ecosystem: "generic",
		},
		Ranges: []osvschema.Range{{
			Type: "SEMVER",
			Events: []osvschema.Event{{
				Introduced: "0",
			}, {
				Fixed: "7.13",
			}},
		}},
		Versions: []string{normalizedVersion},
	}}

	vuln := &inventory.PackageVuln{
		Package: pkg,
		Vulnerability: osvschema.Vulnerability{
			ID:       "CVE-2025-8088",
			Summary:  summary,
			Details:  details,
			Affected: affected,
		},
	}
	return vuln
}

// extractPEVersion tries to extract version info and product name from PE resources
func extractPEVersion(exePath string) (version, prodName string) {
	peFile, err := pe.New(exePath, &pe.Options{})
	if err != nil {
		log.Debugf("Error while opening file: %s, reason: %v", exePath, err)
		// Fallback to filename heuristics
		return extractVersionFromFilename(exePath)
	}
	defer peFile.Close()

	// Parse the PE file
	err = peFile.Parse()
	if err != nil {
		log.Debugf("cve20258088: extractPEVersion: failed to parse PE file: %s, error: %v", exePath, err)
		// Fallback to filename heuristics
		return extractVersionFromFilename(exePath)
	}

	// Extract version resources
	versionInfo, err := peFile.ParseVersionResources()
	if err != nil {
		log.Debugf("cve20258088: extractPEVersion: failed to parse version resources: %s, error: %v", exePath, err)
		// Fallback to filename heuristics
		return extractVersionFromFilename(exePath)
	}

	// Extract version and product name from version resources
	if productVersion, ok := versionInfo["ProductVersion"]; ok && productVersion != "" {
		version = productVersion
	} else if fileVersion, ok := versionInfo["FileVersion"]; ok && fileVersion != "" {
		version = fileVersion
	}

	if productName, ok := versionInfo["ProductName"]; ok && productName != "" {
		prodName = productName
	} else if internalName, ok := versionInfo["InternalName"]; ok && internalName != "" {
		prodName = internalName
	} else if originalFilename, ok := versionInfo["OriginalFilename"]; ok && originalFilename != "" {
		prodName = originalFilename
	}

	// If we couldn't extract from PE resources, fallback to filename heuristics
	if version == "" || prodName == "" {
		fallbackVersion, fallbackProdName := extractVersionFromFilename(exePath)
		if version == "" {
			version = fallbackVersion
		}
		if prodName == "" {
			prodName = fallbackProdName
		}
	}
	return version, prodName
}

// extractVersionFromFilename tries to extract version info and product name from filename (fallback method)
func extractVersionFromFilename(exePath string) (version, prodName string) {
	base := filepath.Base(exePath)
	lower := strings.ToLower(base)

	switch {
	case strings.Contains(lower, "winrar"):
		prodName = "WinRAR"
	case strings.Contains(lower, "unrar"):
		prodName = "UnRAR"
	case strings.Contains(lower, "rar"):
		prodName = "RAR"
	}

	clean := archRegex.ReplaceAllString(lower, "")

	clean = strings.TrimSuffix(clean, ".exe")
	clean = strings.TrimSuffix(clean, ".dll")

	// Find version number (supports 610, 6.10, 6_10, etc.)
	verMatch := verRegex.FindStringSubmatch(clean)
	if verMatch != nil {
		verStr := verMatch[1]
		// Normalize: 610 -> 6.10, 623 -> 6.23, etc.
		if len(verStr) == 3 && !strings.ContainsAny(verStr, "._-") {
			version = fmt.Sprintf("%s.%s", verStr[:1], verStr[1:])
		} else if len(verStr) == 4 && !strings.ContainsAny(verStr, "._-") {
			version = fmt.Sprintf("%s.%s", verStr[:2], verStr[2:])
		} else {
			version = strings.ReplaceAll(verStr, "_", ".")
			version = strings.ReplaceAll(version, "-", ".")
		}
	}
	return version, prodName
}

// normalizeVersion tries to standardize WinRAR version strings
func normalizeVersion(ver string) string {
	ver = strings.TrimSpace(ver)
	ver = strings.ReplaceAll(ver, "_", ".")
	ver = strings.ReplaceAll(ver, "-", ".")
	return ver
}
