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

// Package cve202338408 implements a detector for CVE-2023-38408.
package cve202338408

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/detector"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/semantic"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const (
	// Name of the detector.
	Name = "cve/cve-2023-38408"
)

var (
	// Regex matching the "ssh -A" command.
	sshRegex = regexp.MustCompile(`ssh (.* )?-\w*A`)
	// Regex matching the OpenSSH version.
	openSSHVersionRegex = regexp.MustCompile(`OpenSSH_([^,]+),`)
	// Regex matching the "forwardagent yes" line in ssh config.
	forwardAgentRegex = regexp.MustCompile(`^forwardagent\s+yes`)
)

// Detector is a SCALIBR Detector for CVE-2023-38408.
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
func (Detector) RequiredExtractors() []string { return []string{} }

// DetectedFinding returns generic vulnerability information about what is detected.
func (d Detector) DetectedFinding() inventory.Finding {
	return d.findingForPackage(nil)
}

func (Detector) findingForPackage(dbSpecific map[string]any) inventory.Finding {
	return inventory.Finding{PackageVulns: []*inventory.PackageVuln{{
		Vulnerability: osvschema.Vulnerability{
			ID:      "CVE-2023-38408",
			Summary: "CVE-2023-38408",
			Details: "CVE-2023-38408",
			Affected: []osvschema.Affected{{
				Package: osvschema.Package{
					Name: "openssh",
				},
				Severity: []osvschema.Severity{{
					Type:  osvschema.SeverityCVSSV3,
					Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				}},
				Ranges: []osvschema.Range{{
					Type:   osvschema.RangeEcosystem,
					Events: []osvschema.Event{{Fixed: "9.3.p2"}},
				}},
			}},
			DatabaseSpecific: dbSpecific,
		},
	}}}
}

func isVersionWithinRange(openSSHVersion string, lower string, upper string) (bool, error) {
	lessEq, err1 := versionLessEqual(lower, openSSHVersion)
	greaterEq, err2 := versionLessEqual(openSSHVersion, upper)

	return lessEq && greaterEq, errors.Join(err1, err2)
}

// Scan checks for the presence of the OpenSSH CVE-2023-38408 vulnerability on the filesystem.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	// 1. OpenSSH between and 5.5 and 9.3p1 (inclusive)
	openSSHVersion := getOpenSSHVersion(ctx)
	if openSSHVersion == "" {
		log.Debugf("No OpenSSH version found")
		return inventory.Finding{}, nil
	}
	isVulnVersion, err := isVersionWithinRange(openSSHVersion, "5.5", "9.3p1")

	if err != nil {
		return inventory.Finding{}, err
	}

	if !isVulnVersion {
		log.Debugf("Version %q not vuln", openSSHVersion)
		return inventory.Finding{}, nil
	}
	log.Debugf("Found OpenSSH in range 5.5 to 9.3p1 (inclusive): %v", openSSHVersion)

	// 2. Check ssh config
	configsWithForward := []fileLocations{}
	for _, path := range findSSHConfigs() {
		ls := sshConfigContainsForward(path)
		log.Debugf("ssh config: %q %v", path, ls)
		if len(ls) > 0 {
			configsWithForward = append(configsWithForward, fileLocations{Path: path, LineNumbers: ls})
			log.Debugf("Found ForwardConfig in %s in line(s): %v", path, ls)
		}
	}

	// 3. Socket present
	socketFiles, err := filepath.Glob("/tmp/ssh-*/agent.*")
	if err != nil {
		// The only possible returned error is ErrBadPattern, when pattern is malformed
		return inventory.Finding{}, fmt.Errorf("filepath.Glob(\"/tmp/ssh-*/agent.*\"): %w", err)
	}
	socketExists := len(socketFiles) > 0
	if socketExists {
		log.Debugf("Found Socket at: %v", socketFiles)
	}

	// 4. check bash history
	historyLocations := []fileLocations{}
	for _, path := range findHistoryFiles() {
		ls := findString(path, sshRegex)
		log.Debugf("history file: %q %v", path, ls)
		if len(ls) > 0 {
			historyLocations = append(historyLocations, fileLocations{Path: path, LineNumbers: ls})
			log.Debugf("Found \"ssh .*-A\" in history file %s in line(s): %v", path, ls)
		}
	}

	locations := []string{}
	for _, l := range configsWithForward {
		locations = append(locations, l.Path)
	}
	for _, l := range historyLocations {
		locations = append(locations, l.Path)
	}
	locations = append(locations, socketFiles...)

	dbSpecific := map[string]any{
		"extra": buildExtra(isVulnVersion, configsWithForward, socketFiles, historyLocations, locations),
	}
	return d.findingForPackage(dbSpecific), nil
}

func getOpenSSHVersion(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "ssh", "-V")
	out, err := cmd.CombinedOutput()
	log.Debugf("ssh -V stdout: %s", string(out))
	if err != nil {
		log.Errorf("Command \"ssh -V\": %v", err)
		return ""
	}

	matches := openSSHVersionRegex.FindStringSubmatch(string(out))
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

func buildExtra(isVulnVersion bool, configsWithForward []fileLocations, socketFiles []string, historyLocations []fileLocations, targetLocations []string) string {
	list := []bool{isVulnVersion, len(configsWithForward) > 0, len(socketFiles) > 0, len(historyLocations) > 0}
	slist := []string{}
	for _, l := range list {
		if l {
			slist = append(slist, "1")
		} else {
			slist = append(slist, "0")
		}
	}
	return strings.Join(slist, ":") + "\nLocations:\n" + strings.Join(targetLocations, ",")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func findSSHConfigs() []string {
	r := []string{}

	if fileExists("/root/.ssh/config") {
		r = append(r, "/root/.ssh/config")
	}

	matches, err := filepath.Glob("/home/*/.ssh/config")
	if err != nil {
		log.Errorf("filepath.Glob(\"/home/*/.ssh/config\"): %v", err)
	} else {
		r = append(r, matches...)
	}

	if fileExists("/etc/ssh/ssh_config") {
		r = append(r, "/etc/ssh/ssh_config")
	}

	return r
}

// sshConfigContainsForward returns the line number (0 indexed) of all "ForwardAgent yes" found.
func sshConfigContainsForward(path string) []int {
	f, err := os.Open(path)
	if err != nil {
		log.Warnf("sshConfigContainsForward(%q): %v", path, err)
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	r := []int{}
	i := -1
	for scanner.Scan() {
		i++
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if forwardAgentRegex.MatchString(strings.ToLower(line)) {
			r = append(r, i)
		}
	}

	return r
}

type fileLocations struct {
	Path        string
	LineNumbers []int
}

func versionLessEqual(lower, upper string) (bool, error) {
	// Version format looks like this: 3.7.1p2, 3.7, 3.2.3, 2.9p2
	r, err := semantic.MustParse(lower, "Packagist").CompareStr(upper)

	return r <= 0, err
}

func findHistoryFiles() []string {
	pHistory, err := filepath.Glob("/home/*/.*history")
	if err != nil {
		log.Errorf("filepath.Glob(\"/home/*/.*history\"): %v", err)
	}
	pHistfile, err := filepath.Glob("/home/*/.histfile")
	if err != nil {
		log.Errorf("filepath.Glob(\"/home/*/.histfile\"): %v", err)
	}
	pRootHistory, err := filepath.Glob("/root/.*history")
	if err != nil {
		log.Errorf("filepath.Glob(\"/root/.*history\"): %v", err)
	}
	pRootHistfile, err := filepath.Glob("/root/.histfile")
	if err != nil {
		log.Errorf("filepath.Glob(\"/root/.histfile\"): %v", err)
	}
	return append(append(append(pHistory, pHistfile...), pRootHistory...), pRootHistfile...)
}

func findString(path string, re *regexp.Regexp) []int {
	f, err := os.Open(path)
	if err != nil {
		log.Warnf("findString(%q, %v): %v", path, re, err)
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	r := []int{}
	i := -1
	for scanner.Scan() {
		i++
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if re.MatchString(line) {
			r = append(r, i)
		}
	}

	return r
}
