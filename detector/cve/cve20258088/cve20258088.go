package cve20258088

import (
	"context"
	"fmt"
	"io/fs"
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
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/saferwall/pe"
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
	return []string{"windows/ospackages"}
}

// DetectedFinding returns generic vulnerability information about what is detected.
func (Detector) DetectedFinding() inventory.Finding {
	return inventory.Finding{PackageVulns: []*inventory.PackageVuln{{
		Vulnerability: osvschema.Vulnerability{
			ID:      "CVE-2025-8088",
			Summary: "WinRAR path traversal vulnerability (<7.13)",
			Details: "Detects WinRAR installs or portables < 7.13, using robust and reliable PE analysis.",
		},
	}}}
}

// Scan checks for the presence of the BentoML CVE-2025-8088 vulnerability on the filesystem.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	var findings []*inventory.PackageVuln
	// Match any PE file that could be WinRAR, RAR, UnRAR, UnRAR.dll, including renamed and portable versions
	peRegex := regexp.MustCompile(`(?i)(winrar|rar|unrar).*?(\.exe|\.dll)$`)

	// === Phase 1: Installed packages via package index ===
	if px != nil {
		for _, pkg := range px.GetAll() {
			nameLower := strings.ToLower(pkg.Name)
			if strings.Contains(nameLower, "winrar") {
				normalizedVersion := normalizeVersion(pkg.Version)

				if isAffectedVersion(normalizedVersion) {
					log.Infof("Vulnerable WinRAR package installation found(Uninstall them): Package %s, Version: %s", pkg.Name, normalizedVersion)

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
							Summary:  "WinRAR vulnerable version detected (installed package)",
							Details:  fmt.Sprintf("Installed WinRAR %s detected via package index", normalizedVersion),
							Affected: affected,
						},
					}

					findings = append(findings, vuln)
				}
			}
		}
	}

	// === Phase 2: Filesystem scan (existing logic) ===
	err := fs.WalkDir(scanRoot.FS, scanRoot.Path, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			log.Debugf("cve20258088: Skipping directory or directory entry: %s : error %s", path, err)
			return nil
		}

		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".exe" && ext != ".dll" {
			return nil
		}

		confidence := 0
		var component string

		// Indicator 1: Filename match
		if peRegex.MatchString(d.Name()) {
			confidence += 2
			matches := peRegex.FindStringSubmatch(d.Name())
			if len(matches) > 1 {
				component = matches[1]
			}
		}

		// Indicator 2: PE resource analysis - extract version info from PE resources
		// Now check PE resources for ALL .exe/.dll files, not just regex matches
		version, prodName := extractPEVersion(path)
		if prodName != "" {
			// Check if the product name indicates WinRAR/RAR/UnRAR
			prodNameLower := strings.ToLower(prodName)
			if strings.Contains(prodNameLower, "winrar") || strings.Contains(prodNameLower, "rar") || strings.Contains(prodNameLower, "unrar") {
				confidence += 2
				if component == "" {
					component = prodName
				}
			}
		}

		// Skip if we have no indication this is a WinRAR-related file
		if confidence == 0 {
			log.Debugf("cve20258088: Skipping file %s, no WinRAR indicators found", d.Name())
			return nil
		}

		// Only report if confidence is high enough
		if confidence >= 2 && version != "" {
			normalizedVersion := normalizeVersion(version)

			if isAffectedVersion(normalizedVersion) {
				log.Infof("Vulnerable WinRAR package found(Delete them): %s, Package: %s, Version: %s", path, prodName, normalizedVersion)
				pkg := &extractor.Package{
					Name:         component,
					Version:      normalizedVersion,
					PURLType:     "generic",
					Locations:    []string{path},
					SourceCode:   &extractor.SourceCodeIdentifier{},
					LayerDetails: &extractor.LayerDetails{},
					Metadata:     nil,
				}

				affected := []osvschema.Affected{{
					Package: osvschema.Package{
						Name:      component,
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
						Summary:  "WinRAR vulnerable version detected",
						Details:  fmt.Sprintf("%s found at %s, version: %s (confidence: %d)", component, path, normalizedVersion, confidence),
						Affected: affected,
					},
				}
				findings = append(findings, vuln)
			}
		}
		return nil
	})
	if err != nil {
		return inventory.Finding{}, err
	}

	if len(findings) == 0 {
		return inventory.Finding{}, nil
	}
	return inventory.Finding{PackageVulns: findings}, nil
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

	archRegex := regexp.MustCompile(`(?i)(x64|x86|arm64|arm32|portable)`)
	clean := archRegex.ReplaceAllString(lower, "")

	clean = strings.TrimSuffix(clean, ".exe")
	clean = strings.TrimSuffix(clean, ".dll")

	// Find version number (supports 610, 6.10, 6_10, etc.)
	verRegex := regexp.MustCompile(`(\d+[\._-]?\d*)`)
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

// isAffectedVersion returns true if version < 7.13
func isAffectedVersion(ver string) bool {
	parts := strings.Split(ver, ".")
	if len(parts) < 2 {
		return false
	}
	major := atoi(parts[0])
	minor := atoi(parts[1])

	if major < 7 || (major == 7 && minor < 13) {
		return true
	}
	return false
}

func atoi(s string) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0
	}
	return n
}

// normalizeVersion tries to standardize WinRAR version strings
func normalizeVersion(ver string) string {
	ver = strings.TrimSpace(ver)
	ver = strings.ReplaceAll(ver, "_", ".")
	ver = strings.ReplaceAll(ver, "-", ".")
	return ver
}
