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

// Package cve20257775 implements a SCALIBR Detector for CVE-2025-7775
package cve20257775

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/ova"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/vdi"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/vmdk"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/semantic"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// Precompiled regex patterns
var (
	// Matches filenames like ns-14.1-47.48.gz
	versionFileRegex = regexp.MustCompile(`ns-(\d+\.\d+)-(\d+\.\d+)\.\S+`)
	// Matches version strings like ns-14.1-47.48 in loader.conf content
	versionLoaderRegex = regexp.MustCompile(`ns-(\d+\.\d+)-(\d+\.\d+)`)
	// Matches nsversion content like "NS14.1 Build 21.12"
	versionNsRegex = regexp.MustCompile(`NS(\d+\.\d+) Build (\d+\.\d+)`)
	// Matches suspicious ns.conf patterns
	// https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX694938
	configRegexes = []*regexp.Regexp{
		regexp.MustCompile(`add\s+authentication\s+vserver.*`),
		regexp.MustCompile(`add\s+vpn\s+vserver.*`),
		regexp.MustCompile(`enable\s+ns\s+feature\s+lb.*`),
		regexp.MustCompile(`add\s+serviceGroup\s+\S+\s+(HTTP_QUIC|SSL|HTTP).*`),
		regexp.MustCompile(`add\s+server\s+\S+\s+[0-9a-fA-F:]+`),
		regexp.MustCompile(`bind\s+servicegroup\s+\S+\s+[0-9a-fA-F:]+`),
		regexp.MustCompile(`add\s+lb\s+vserver\s+\S+\s+(HTTP_QUIC|SSL|HTTP).*`),
		regexp.MustCompile(`bind\s+lb\s+vserver\s+\S+\s+\S+`),
		regexp.MustCompile(`add\s+server\s+\S+\s+-queryType\s+AAAA`),
		regexp.MustCompile(`add\s+service\s+\S+\s+[0-9a-fA-F:]+`),
	}
)

const (
	// Name of the detector.
	Name = "cve/cve-2025-7775"
)

// Options contains HostScan flag to trigger a host filesystem scan.
type Options struct {
	// HostScan triggers the full Host filesystem scan.
	// Covers the edge case when scalibr is running on a NetScaler configured machine.
	// Default (false): if true, perform the Host FS walk to look for NetScaler Artifacts on the host filesystem.
	HostScan bool
}

// Detector is a SCALIBR Detector for CVE-2025-7775.
type Detector struct {
	opts Options
}

// New returns a detector.
func New(opts Options) detector.Detector {
	return &Detector{opts: opts}
}

// NewDefault returns a detector with default options (HostScan disabled).
func NewDefault() detector.Detector {
	return &Detector{
		opts: Options{
			HostScan: false,
		},
	}
}

// Name of the detector.
func (Detector) Name() string { return Name }

// Version of the detector.
func (Detector) Version() int { return 0 }

// Requirements of the detector.
func (Detector) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// RequiredExtractors of the detector.
func (Detector) RequiredExtractors() []string {
	return []string{ova.Name}
}

// DetectedFinding returns generic vulnerability information about what is detected.
func (d Detector) DetectedFinding() inventory.Finding {
	return d.findingForPackage(nil)
}

func (Detector) findingForPackage(dbSpecific map[string]any) inventory.Finding {
	pkg := &extractor.Package{
		Name:     "NetScaler",
		PURLType: "generic",
	}
	return inventory.Finding{PackageVulns: []*inventory.PackageVuln{{
		Vulnerability: osvschema.Vulnerability{
			ID:      "CVE-2025-7775",
			Summary: "Memory overflow vulnerability leading to Remote Code Execution and/or Denial of Service",
			Details: "Memory overflow vulnerability leading to Remote Code Execution and/or Denial of Service in NetScaler ADC and NetScaler Gateway",
			Affected: inventory.PackageToAffected(pkg, "12.1-55.330, 13.1-59.22, 14.1-47.48", &osvschema.Severity{
				Type:  osvschema.SeverityCVSSV3,
				Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			}),
			DatabaseSpecific: dbSpecific,
		},
	}}}
}

// Scan checks for the presence of the CVE-2025-7775 vulnerability on the filesystem.
// Note: filesystem given in scanRoot corresponds to the Host filesystem on which the tool is running. Not the virtual filesystem.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	var findings []*inventory.PackageVuln

	// Host filesystem scan
	if d.opts.HostScan {
		realExtra, err := detectInFS(scanRoot.FS)
		if err != nil {
			log.Infof("detectInFS for real FS failed: %v", err)
		}
		if realExtra != "" {
			dbSpecific := map[string]any{"extra": realExtra}
			findings = append(findings, d.findingForPackage(dbSpecific).PackageVulns[0])
		}
	}

	// Embedded filesystem scan
	if px != nil {
		for _, pkg := range px.GetAllOfType(purl.TypeOva) {
			for _, path := range pkg.Locations {
				_, err := os.Stat(path)
				if err != nil {
					continue
				}
				if strings.HasSuffix(strings.ToLower(path), ".vmdk") || strings.HasSuffix(strings.ToLower(path), ".vdi") {
					info, err := os.Stat(path)
					if err != nil {
						log.Infof("os.Stat(%q) failed: %v", path, err)
						continue
					}
					var Extractor filesystem.Extractor
					if strings.HasSuffix(strings.ToLower(path), ".vmdk") {
						Extractor = vmdk.New()
					}
					if strings.HasSuffix(strings.ToLower(path), ".vdi") {
						Extractor = vdi.New()
					}
					input := &filesystem.ScanInput{
						Path:   path,
						Root:   "/",
						Info:   info,
						Reader: nil,
						FS:     nil,
					}
					inv, err := Extractor.Extract(ctx, input)
					if err != nil {
						log.Infof("Extract(%q) failed: %v", path, err)
						continue
					}
					if len(inv.EmbeddedFSs) == 0 {
						log.Infof("Extract returned no DiskImages")
						continue
					}

					for _, embeddedFS := range inv.EmbeddedFSs {
						efs, err := embeddedFS.GetEmbeddedFS(ctx)
						if err != nil {
							log.Infof("GetEmbeddedFS() failed: %v", err)
							continue
						}

						embeddedExtra, err := detectInFS(efs)
						if err != nil {
							log.Infof("detectInFS for embedded FS failed: %v", err)
						}

						if embeddedExtra != "" {
							dbSpecific := map[string]any{"extra": embeddedExtra}
							findings = append(findings, d.findingForPackage(dbSpecific).PackageVulns[0])
						}
					}
				}
			}
		}
	}

	if len(findings) == 0 {
		return inventory.Finding{}, nil
	}
	return inventory.Finding{PackageVulns: findings}, nil
}

// detectInFS scans the given filesystem for vulnerable versions and suspicious configs.
func detectInFS(fsys fs.FS) (string, error) {
	vulnerableVersions := make(map[string]struct{}) // ver-build keys
	versionLocations := []string{}
	var nsConfPath string
	hasSuspiciousConfig := false

	err := fs.WalkDir(fsys, ".", func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			log.Warnf("Walk error for %s: %v", path, err)
			return nil
		}
		if de.IsDir() {
			return nil
		}

		baseName := de.Name()
		// Check filename for version
		if versionFileRegex.MatchString(baseName) {
			matches := versionFileRegex.FindStringSubmatch(baseName)
			if len(matches) == 3 {
				ver, build := matches[1], matches[2]
				if isVulnerable(ver, build) {
					vulnerableVersions[ver+"-"+build] = struct{}{}
					versionLocations = append(versionLocations, path)
				}
			}
		}

		// Read file content
		f, err := fsys.Open(path)
		if err != nil {
			log.Debugf("Failed to open %s: %v", path, err)
			return nil
		}
		defer f.Close()
		content, err := io.ReadAll(f)
		if err != nil {
			log.Debugf("Failed to read %s: %v", path, err)
			return nil
		}
		contentStr := string(content)

		switch strings.ToLower(baseName) {
		case "loader.conf":
			lines := strings.Split(contentStr, "\n")
			for _, line := range lines {
				if versionLoaderRegex.MatchString(line) {
					matches := versionLoaderRegex.FindStringSubmatch(line)
					if len(matches) == 3 {
						ver, build := matches[1], matches[2]
						if isVulnerable(ver, build) {
							vulnerableVersions[ver+"-"+build] = struct{}{}
							versionLocations = append(versionLocations, path)
						}
					}
				}
			}
		case "nsversion":
			if versionNsRegex.MatchString(contentStr) {
				matches := versionNsRegex.FindStringSubmatch(contentStr)
				if len(matches) == 3 {
					ver, build := matches[1], matches[2]
					if isVulnerable(ver, build) {
						vulnerableVersions[ver+"-"+build] = struct{}{}
						versionLocations = append(versionLocations, path)
					}
				}
			}
		case "ns.conf":
			nsConfPath = path
			for _, re := range configRegexes {
				if re.MatchString(contentStr) {
					hasSuspiciousConfig = true
					break
				}
			}
			lines := strings.Split(contentStr, "\n")
			for _, line := range lines {
				if versionLoaderRegex.MatchString(line) {
					matches := versionLoaderRegex.FindStringSubmatch(line)
					if len(matches) == 3 {
						ver, build := matches[1], matches[2]
						if isVulnerable(ver, build) {
							vulnerableVersions[ver+"-"+build] = struct{}{}
							versionLocations = append(versionLocations, path)
						}
					}
				}
			}
		}

		return nil
	})
	if err != nil {
		return "", fmt.Errorf("WalkDir failed: %w", err)
	}

	if len(vulnerableVersions) > 0 && hasSuspiciousConfig {
		var verBuilds []string
		for vb := range vulnerableVersions {
			verBuilds = append(verBuilds, vb)
		}
		sort.Strings(verBuilds)
		locations := versionLocations
		if nsConfPath != "" {
			locations = append(locations, nsConfPath)
		}
		extra := fmt.Sprintf("Vulnerable version(s): %s\nLocations: %s\nConfig file: %s", strings.Join(verBuilds, ", "), strings.Join(locations, ", "), nsConfPath)
		return extra, nil
	}

	return "", nil
}

// isVulnerable checks if the version and build are in the affected range.
func isVulnerable(ver, build string) bool {
	if buildversion, err := semantic.Parse(build, "Go"); err == nil {
		switch ver {
		case "14.1":
			if cmp, err := buildversion.CompareStr("47.48"); err == nil && cmp < 0 {
				return true
			}
			return false
		case "13.1":
			if cmp, err := buildversion.CompareStr("59.22"); err == nil && cmp < 0 {
				return true
			}
			return false
		case "12.1":
			if cmp, err := buildversion.CompareStr("55.330"); err == nil && cmp < 0 {
				return true
			}
			return false
		}
	}

	log.Infof("Failed to parse build number %s", build)
	return false
}
