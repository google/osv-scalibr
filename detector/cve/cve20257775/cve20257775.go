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
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/misc/netscaler"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/semantic"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

// Precompiled regex patterns
var (
	// Matches version strings like 14.1-47.48
	versionRegex = regexp.MustCompile(`(\d+\.\d+)-(\d+\.\d+)`)
	// Matches vulnerable ns.conf patterns
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

// Detector is a SCALIBR Detector for CVE-2025-7775.
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
	return &plugin.Capabilities{}
}

// RequiredExtractors of the detector.
func (Detector) RequiredExtractors() []string {
	return []string{netscaler.Name}
}

// DetectedFinding returns generic vulnerability information about what is detected.
func (d Detector) DetectedFinding() inventory.Finding {
	return d.findingForPackage(nil)
}

func (d Detector) findingForPackage(dbSpecific *structpb.Struct) inventory.Finding {
	pkg := &extractor.Package{
		Name:     "NetScaler",
		PURLType: "generic",
	}
	return inventory.Finding{PackageVulns: []*inventory.PackageVuln{{
		Vulnerability: &osvpb.Vulnerability{
			Id:      "CVE-2025-7775",
			Summary: "Memory overflow vulnerability leading to Remote Code Execution and/or Denial of Service in NetScaler ADC and NetScaler Gateway",
			Details: "Memory overflow vulnerability leading to Remote Code Execution and/or Denial of Service in NetScaler ADC and NetScaler Gateway",
			Affected: inventory.PackageToAffected(pkg, "12.1-55.330, 13.1-59.22, 14.1-47.48", &osvpb.Severity{
				Type:  osvpb.Severity_CVSS_V3,
				Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			}),
			DatabaseSpecific: dbSpecific,
		},
	}}}
}

// Scan checks for the presence of the CVE-2025-7775 vulnerability on the filesystem.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	if px == nil {
		return inventory.Finding{}, nil
	}

	var findings []*inventory.PackageVuln
	seen := make(map[string]struct{})

	for _, pkg := range px.GetAll() {
		if pkg.Name == "NetScaler" {
			// Check if package version is vulnerable
			if !isVulnerable(pkg.Version) {
				continue
			}

			for _, location := range pkg.Locations {
				// fs represents the filesystem where the vulnerable package was found.
				// It's required to prevent duplicate security findings originating from
				// the same filesystem.
				var fs string

				// NetScaler instance might be inside embedded filesystems denoted by ":".
				// So we need to differentiate whether it's an embedded filesystem or host filesystem.
				parts := strings.Split(location, ":")
				if len(parts) >= 2 {
					// Windows paths contain ":" as part of the drive letter (e.g., "D:\path\file.vmdk"),
					// which interferes with splitting logic based on ":" delimiters.
					// Therefore, when running on Windows, we must skip the drive letter and only use
					// its path.
					//
					// Example formats:
					//   Linux/macOS: /path/to/valid.vmdk:1:netscaler/...
					//   Windows:     D:\path\to\valid.vmdk:1:netscaler\...
					if os.PathSeparator == '\\' {
						fs = strings.Join(parts[1:3], ":")
					} else {
						fs = strings.Join(parts[:2], ":")
					}
				} else {
					// If we're here, then that means it's a package parsed from host filesystem.
					// Form: /nsconfig/nsversion, /flash/boot/loader.conf, etc.

					// "HostFS" is a special identifier representing the host filesystem.
					// If an entry for "HostFS" already exists in the `seen` map, skip processing it
					// to prevent duplicate security findings originating from the same host filesystem.
					fs = "HostFS"
				}

				if _, exists := seen[fs]; exists {
					continue
				}
				seen[fs] = struct{}{}

				// Check ns.conf using pkg.Metadata (scalibrfs.FS)
				fsys, ok := pkg.Metadata.(scalibrfs.FS)
				if !ok {
					continue
				}

				f, err := fsys.Open("nsconfig/ns.conf")
				if err != nil {
					continue
				}
				defer f.Close()

				hasVulnerableConfig := false

				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					if ctx.Err() != nil {
						break
					}

					// Fetch the line
					line := scanner.Text()

					// Check for vulnerable config patterns
					for _, re := range configRegexes {
						if re.MatchString(line) {
							hasVulnerableConfig = true
							break
						}
					}
				}

				if hasVulnerableConfig {
					// Add locations and ns.conf to dbSpecific
					locations := pkg.Locations
					dbSpecific := &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"extra": {Kind: &structpb.Value_StringValue{StringValue: fmt.Sprintf("Vulnerable version: %s; Locations: %s", pkg.Version, strings.Join(locations, ", "))}},
						},
					}
					finding := d.findingForPackage(dbSpecific).PackageVulns[0]
					finding.Package = pkg // Include the package details
					findings = append(findings, finding)
				}
			}
		}
	}

	return inventory.Finding{PackageVulns: findings}, nil
}

// isVulnerable checks if the version and build are in the affected range.
func isVulnerable(version string) bool {
	matches := versionRegex.FindStringSubmatch(version)
	if len(matches) != 3 {
		return false
	}

	ver, build := matches[1], matches[2]
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
	return false
}
