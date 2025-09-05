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

//go:build !windows

// Package dockersocket implements a detector for Docker socket exposure vulnerabilities.
package dockersocket

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"

	"github.com/google/osv-scalibr/detector"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the detector.
	Name = "dockersocket"
)

// Detector is a SCALIBR Detector for Docker socket exposure vulnerabilities.
type Detector struct{}

// New returns a detector.
func New() detector.Detector {
	return &Detector{}
}

// Name of the detector.
func (Detector) Name() string { return Name }

// Version of the detector.
func (Detector) Version() int { return 0 }

// RequiredExtractors returns an empty list as there are no dependencies.
func (Detector) RequiredExtractors() []string { return []string{} }

// Requirements of the Detector.
func (Detector) Requirements() *plugin.Capabilities { return &plugin.Capabilities{OS: plugin.OSUnix} }

// Scan starts the scan.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	return d.ScanFS(ctx, scanRoot.FS, px)
}

// DetectedFinding returns generic vulnerability information about what is detected.
func (d Detector) DetectedFinding() inventory.Finding {
	return d.findingForTarget(nil)
}

func (Detector) findingForTarget(target *inventory.GenericFindingTargetDetails) inventory.Finding {
	return inventory.Finding{GenericFindings: []*inventory.GenericFinding{{
		Adv: &inventory.GenericFindingAdvisory{
			ID: &inventory.AdvisoryID{
				Publisher: "SCALIBR",
				Reference: "docker-socket-exposure",
			},
			Title: "Docker Socket Exposure Detection",
			Description: "Docker socket exposure can lead to privilege escalation and container escape vulnerabilities. " +
				"Insecure Docker socket permissions, daemon configuration, or systemd service settings " +
				"may allow unauthorized access to the Docker API, potentially compromising the entire host system.",
			Recommendation: "Secure Docker socket by: 1) Setting appropriate file permissions (660) on /var/run/docker.sock, " +
				"2) Configuring daemon.json to use TLS authentication for remote API access, " +
				"3) Ensuring systemd service configurations use secure API bindings with proper authentication.",
			Sev: inventory.SeverityHigh,
		},
		Target: target,
	}}}
}

// ScanFS starts the scan from a pseudo-filesystem.
func (d Detector) ScanFS(ctx context.Context, fsys fs.FS, px *packageindex.PackageIndex) (inventory.Finding, error) {
	var issues []string

	// Check for context timeout
	if ctx.Err() != nil {
		return inventory.Finding{}, ctx.Err()
	}

	// Check Docker socket file permissions
	if socketIssues := d.checkDockerSocketPermissions(fsys); len(socketIssues) > 0 {
		issues = append(issues, socketIssues...)
	}

	// Check for context timeout
	if ctx.Err() != nil {
		return inventory.Finding{}, ctx.Err()
	}

	// Check Docker daemon configuration
	if daemonIssues := d.checkDockerDaemonConfig(ctx, fsys); len(daemonIssues) > 0 {
		issues = append(issues, daemonIssues...)
	}

	// Check for context timeout
	if ctx.Err() != nil {
		return inventory.Finding{}, ctx.Err()
	}

	// Check systemd service configuration
	if systemdIssues := d.checkSystemdServiceConfig(ctx, fsys); len(systemdIssues) > 0 {
		issues = append(issues, systemdIssues...)
	}

	if len(issues) == 0 {
		return inventory.Finding{}, nil
	}

	target := &inventory.GenericFindingTargetDetails{Extra: strings.Join(issues, "; ")}
	return d.findingForTarget(target), nil
}

// checkDockerSocketPermissions checks /var/run/docker.sock for insecure permissions.
func (d Detector) checkDockerSocketPermissions(fsys fs.FS) []string {
	var issues []string

	f, err := fsys.Open("var/run/docker.sock")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Socket doesn't exist, Docker likely not installed - no issue
			return issues
		}
		// Cannot access socket - potential permission issue but can't verify
		return issues
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return issues
	}

	// Check if socket is world-readable or world-writable
	perms := info.Mode().Perm()
	if perms&0004 != 0 {
		issues = append(issues, fmt.Sprintf("Docker socket is world-readable (permissions: %03o)", perms))
	}
	if perms&0002 != 0 {
		issues = append(issues, fmt.Sprintf("Docker socket is world-writable (permissions: %03o)", perms))
	}

	// Check ownership
	stat, ok := info.Sys().(*syscall.Stat_t)
	if ok {
		if stat.Uid != 0 {
			issues = append(issues, fmt.Sprintf("Docker socket owner is not root (uid: %d)", stat.Uid))
		}
		// Note: Group ownership of 'docker' (typically GID varies) is acceptable
	}

	return issues
}

// dockerDaemonConfig represents the structure of /etc/docker/daemon.json.
type dockerDaemonConfig struct {
	Hosts []string `json:"hosts"`
}

// checkDockerDaemonConfig checks /etc/docker/daemon.json for insecure host configurations.
func (d Detector) checkDockerDaemonConfig(ctx context.Context, fsys fs.FS) []string {
	var issues []string

	f, err := fsys.Open("etc/docker/daemon.json")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Config file doesn't exist - no issue to report
			return issues
		}
		return issues
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		return issues
	}

	var config dockerDaemonConfig
	if err := json.Unmarshal(content, &config); err != nil {
		// Invalid JSON - potential issue but not our concern
		return issues
	}

	// Check for insecure host bindings
	for _, host := range config.Hosts {
		// Check for context timeout
		if ctx.Err() != nil {
			return issues
		}
		if strings.HasPrefix(host, "tcp://") {
			// TCP binding without TLS - potential security issue
			issues = append(issues, fmt.Sprintf("Insecure TCP binding in daemon.json: %q (consider using TLS)", host))
		}
	}

	return issues
}

// checkSystemdServiceConfig checks Docker systemd service files for insecure configurations.
func (d Detector) checkSystemdServiceConfig(ctx context.Context, fsys fs.FS) []string {
	var issues []string

	// Check common systemd service locations
	servicePaths := []string{
		"etc/systemd/system/docker.service",
		"lib/systemd/system/docker.service",
		"usr/lib/systemd/system/docker.service",
	}

	for _, path := range servicePaths {
		// Check for context timeout
		if ctx.Err() != nil {
			return issues
		}
		if serviceIssues := d.checkSystemdServiceFile(ctx, fsys, path); len(serviceIssues) > 0 {
			issues = append(issues, serviceIssues...)
		}
	}

	return issues
}

// checkSystemdServiceFile checks a specific systemd service file for insecure Docker configurations.
func (d Detector) checkSystemdServiceFile(ctx context.Context, fsys fs.FS, path string) []string {
	var issues []string

	f, err := fsys.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Service file doesn't exist - no issue
			return issues
		}
		return issues
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// Check for context timeout
		if ctx.Err() != nil {
			return issues
		}

		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "ExecStart=") {
			// Check for insecure -H tcp:// flags in ExecStart
			if strings.Contains(line, "-H tcp://") && !strings.Contains(line, "--tls") {
				issues = append(issues, fmt.Sprintf("Insecure TCP binding in %q: %q (missing TLS)", path, line))
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return issues
	}

	return issues
}
