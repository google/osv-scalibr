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

// Package cve202233891 implements a detector for CVE-2022-33891.
// To test, install a vulnerable pyspark version: python3 -m pip install pyspark==3.2.1
// Run the spark-shell: spark-shell --conf spark.acls.enable=true
// If spark-shell crashes with an error, change your java version to an old one: sudo update-alternatives --config java (JAVA 11 works)
// Run this detector.
package cve202233891

import (
	"context"
	"fmt"
	"io/fs"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type sparkUIPackageNames struct {
	packageType      string
	name             string
	affectedVersions []string
}

const (
	// Name of the detector.
	Name = "cve/cve-2022-33891"

	defaultTimeout = 5 * time.Second
)

var (
	seededRand        = rand.New(rand.NewSource(time.Now().UnixNano()))
	sparkServersPorts = []int{4040, 8080}
	sparkUIPackages   = []sparkUIPackageNames{
		{
			packageType: "pypi",
			name:        "pyspark",
			affectedVersions: []string{
				"3.0.0",
				"3.0.1",
				"3.0.2",
				"3.0.3",
				"3.1.1",
				"3.1.2",
				"3.2.0",
				"3.2.1",
			},
		},
	}
)

// Detector is a SCALIBR Detector for CVE-2022-33891.
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
	return &plugin.Capabilities{OS: plugin.OSLinux, DirectFS: true, RunningSystem: true}
}

// RequiredExtractors returns  the list of OS package extractors needed to detect
// the presence of the pyspark package in various OSes.
func (Detector) RequiredExtractors() []string {
	return []string{wheelegg.Name}
}

// DetectedFinding returns generic vulnerability information about what is detected.
func (d Detector) DetectedFinding() inventory.Finding {
	return d.findingForPackage(nil)
}

func (Detector) findingForPackage(dbSpecific map[string]any) inventory.Finding {
	pkg := &extractor.Package{
		Name:     "pyspark",
		PURLType: "pypi",
	}
	return inventory.Finding{PackageVulns: []*inventory.PackageVuln{{
		Vulnerability: osvschema.Vulnerability{
			ID:      "CVE-2022-33891",
			Summary: "CVE-2022-33891",
			Details: "CVE-2022-33891",
			Affected: inventory.PackageToAffected(pkg, "3.2.2", &osvschema.Severity{
				Type:  osvschema.SeverityCVSSV3,
				Score: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			}),
			DatabaseSpecific: dbSpecific,
		},
	}}}
}

// Scan scans for the vulnerability, doh!
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	sparkUIVersion, pkg, affectedVersions := findApacheSparkUIPackage(px)
	if sparkUIVersion == "" {
		log.Debugf("No Apache Spark UI version found")
		return inventory.Finding{}, nil
	}

	isVulnVersion := false
	for _, affected := range affectedVersions {
		if sparkUIVersion == affected {
			isVulnVersion = true
		}
	}

	if !isVulnVersion {
		log.Infof("Version %q not vuln", sparkUIVersion)
		return inventory.Finding{}, nil
	}
	log.Infof("Found Potentially vulnerable Apache Spark UI version %v", sparkUIVersion)

	vulnerable := false
	for _, port := range sparkServersPorts {
		randFilePath := "/tmp/" + randomString(16)
		testCmd := "touch%20" + randFilePath
		retCode := sparkUIHTTPQuery(ctx, "127.0.0.1", port, testCmd)
		// We expect to receive a 403 error
		if retCode != 403 {
			log.Infof("Version %q not vuln (HTTP query didn't return 403: %v)", sparkUIVersion, retCode)
			continue
		}

		if fileExists(scanRoot.FS, randFilePath) {
			err := os.Remove(randFilePath)
			if err != nil {
				log.Infof("Error when removing file %v: %v", randFilePath, err)
			}
			log.Infof("File %v found, this server is vulnerable. Removing the file now", randFilePath)
			vulnerable = true
			break
		}
		log.Infof("Version %q not vuln (Temp file not found)", sparkUIVersion)
	}
	if !vulnerable {
		return inventory.Finding{}, nil
	}

	dbSpecific := map[string]any{
		"extra": fmt.Sprintf("%s %s %s", pkg.Name, pkg.Version, strings.Join(pkg.Locations, ", ")),
	}
	return d.findingForPackage(dbSpecific), nil
}

func sparkUIHTTPQuery(ctx context.Context, sparkDomain string, sparkPort int, cmdExec string) int {
	client := &http.Client{Timeout: defaultTimeout}

	targetURL := fmt.Sprintf("http://%s/?doAs=`%s`", net.JoinHostPort(sparkDomain, strconv.Itoa(sparkPort)), cmdExec)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	req.Header.Add("Accept", "*/*")
	resp, err := client.Do(req)

	if err != nil {
		log.Infof("Error when sending request %s to the server", targetURL)
		return 0
	}

	defer resp.Body.Close()

	return resp.StatusCode
}

func findApacheSparkUIPackage(px *packageindex.PackageIndex) (string, *extractor.Package, []string) {
	for _, r := range sparkUIPackages {
		pkg := px.GetSpecific(r.name, r.packageType)
		for _, p := range pkg {
			return p.Version, p, r.affectedVersions
		}
	}
	return "", nil, []string{}
}

func fileExists(filesys scalibrfs.FS, path string) bool {
	_, err := fs.Stat(filesys, path)
	return !os.IsNotExist(err)
}

func randomString(length int) string {
	charSet := "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ"
	b := make([]byte, length)
	for i := range b {
		b[i] = charSet[seededRand.Intn(len(charSet)-1)]
	}
	return string(b)
}
