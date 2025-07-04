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

// Package filebrowser implements a detector for weak/guessable passwords
// on a filebrowser instance.
// To test and install filebrowser, simply follow the instructions in
// https://filebrowser.org/installation
package filebrowser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/osv-scalibr/detector"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the detector.
	Name = "weakcredentials/filebrowser"

	fileBrowserIP  = "127.0.0.1"
	requestTimeout = 2 * time.Second
)

var (
	fileBrowserPorts = []int{
		5080,
		8080,
		80,
	}
)

// Detector is a SCALIBR Detector for weak/guessable passwords from /etc/shadow.
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
	return &plugin.Capabilities{OS: plugin.OSLinux, RunningSystem: true}
}

// RequiredExtractors returns an empty list as there are no dependencies.
func (Detector) RequiredExtractors() []string { return []string{} }

// DetectedFinding returns generic vulnerability information about what is detected.
func (d Detector) DetectedFinding() inventory.Finding {
	return d.finding()
}

func (Detector) finding() inventory.Finding {
	return inventory.Finding{GenericFindings: []*inventory.GenericFinding{{
		Adv: &inventory.GenericFindingAdvisory{
			ID: &inventory.AdvisoryID{
				Publisher: "SCALIBR",
				Reference: "file-browser-weakcredentials",
			},
			Title: "Filebrowser default credentials",
			Description: "Filebrowser is a self-hosted web application to manage files and folders. " +
				"It has been detected that the default credentials are in use, which can be exploited by an" +
				" attacker to execute arbitrary commands on the affected system.",
			Recommendation: "If you have devlify installed, run 'devlify update' to apply the fix." +
				" Follow the prompts until you get a 'Configuration is done!' message." +
				" If the update succeeded, the output of the 'podman ps' command should no longer" +
				" show the File Browser container." +
				" In all other instances where filebrowser is installed as a stand-alone, the vulnerability" +
				" can be remediated by changing the default credentials through the Web UI and restarting the service" +
				" or by uninstalling the filebrowser service/container.",
			Sev: inventory.SeverityCritical,
		},
	}}}
}

// Scan starts the scan.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	for _, fileBrowserPort := range fileBrowserPorts {
		if ctx.Err() != nil {
			return inventory.Finding{}, ctx.Err()
		}
		if !isVulnerable(ctx, fileBrowserIP, fileBrowserPort) {
			continue
		}
		return d.finding(), nil
	}

	return inventory.Finding{}, nil
}

func isVulnerable(ctx context.Context, fileBrowserIP string, fileBrowserPort int) bool {
	if !checkAccessibility(ctx, fileBrowserIP, fileBrowserPort) {
		return false
	}
	if !checkLogin(ctx, fileBrowserIP, fileBrowserPort) {
		return false
	}
	return true
}

// checkAccessibility checks if the filebrowser instance is accessible given an IP and port.
func checkAccessibility(ctx context.Context, fileBrowserIP string, fileBrowserPort int) bool {
	client := &http.Client{Timeout: requestTimeout}
	targetURL := fmt.Sprintf("http://%s/", net.JoinHostPort(fileBrowserIP, strconv.Itoa(fileBrowserPort)))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		log.Infof("Error while constructing request %s to the server: %v", targetURL, err)
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			log.Infof("Timeout exceeded when accessing %s", targetURL)
		} else {
			log.Debugf("Error when sending request %s to the server: %v", targetURL, err)
		}
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	// Expected size for the response is around 6 kilobytes.
	if resp.ContentLength > 20*1024 {
		log.Infof("Filesize is too large: %d bytes", resp.ContentLength)
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Infof("Error reading response body: %v", err)
		return false
	}

	bodyString := string(bodyBytes)
	if !strings.Contains(bodyString, "File Browser") {
		log.Infof("Response body does not contain 'File Browser'")
		return false
	}

	return true
}

// checkLogin checks if the login with default credentials is successful.
func checkLogin(ctx context.Context, fileBrowserIP string, fileBrowserPort int) bool {
	client := &http.Client{Timeout: requestTimeout}
	targetURL := fmt.Sprintf("http://%s/api/login", net.JoinHostPort(fileBrowserIP, strconv.Itoa(fileBrowserPort)))

	//nolint:errchkjson // this is a static struct, so it cannot fail
	requestBody, _ := json.Marshal(map[string]string{
		"username":  "admin",
		"password":  "admin",
		"recaptcha": "",
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, io.NopCloser(bytes.NewBuffer(requestBody)))
	if err != nil {
		log.Infof("Error while constructing request %s to the server: %v", targetURL, err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			log.Infof("Timeout exceeded when accessing %s", targetURL)
		} else {
			log.Infof("Error when sending request %s to the server: %v", targetURL, err)
		}
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}
