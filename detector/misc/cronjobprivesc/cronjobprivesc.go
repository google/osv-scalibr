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

// Package cronjobprivesc implements a detector for misconfigured cron jobs and scheduled tasks that could lead to privilege escalation.
package cronjobprivesc

import (
	"context"
	"io/fs"
	"strings"

	"github.com/google/osv-scalibr/detector"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the detector.
	Name = "cronjobprivesc"
)

// Detector is a SCALIBR Detector for cron job and scheduled task privilege escalation vulnerabilities.
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
func (Detector) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

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
				Reference: "cronjobs-privilege-escalation",
			},
			Title: "Misconfigured Cron Jobs and Scheduled Tasks",
			Description: "Cron jobs and scheduled tasks running with elevated privileges that reference " +
				"scripts or binaries with insecure file permissions can lead to privilege escalation. " +
				"This includes jobs running as root that execute files in world-writable directories, " +
				"scripts with overly permissive permissions, or tasks that allow unauthorized modification.",
			Recommendation: "Secure cron jobs and scheduled tasks by: 1) Ensuring scripts and binaries " +
				"executed by privileged jobs have restrictive permissions (644 for scripts, 755 for binaries), " +
				"2) Avoiding execution of files in world-writable directories like /tmp, " +
				"3) Setting proper ownership (root:root) for privileged job executables, " +
				"4) Using absolute paths in cron jobs to prevent PATH manipulation attacks.",
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

	// Check all platform types regardless of runtime OS since we're working with abstract filesystems
	// Check Linux cron jobs
	if linuxIssues := d.checkLinuxCronJobs(ctx, fsys); len(linuxIssues) > 0 {
		issues = append(issues, linuxIssues...)
	}

	// Check for context timeout
	if ctx.Err() != nil {
		return inventory.Finding{}, ctx.Err()
	}

	// Check Windows scheduled tasks
	if windowsIssues := d.checkWindowsTaskScheduler(ctx, fsys); len(windowsIssues) > 0 {
		issues = append(issues, windowsIssues...)
	}

	// Check for context timeout
	if ctx.Err() != nil {
		return inventory.Finding{}, ctx.Err()
	}

	// Check macOS launchd
	if macIssues := d.checkMacOSLaunchd(ctx, fsys); len(macIssues) > 0 {
		issues = append(issues, macIssues...)
	}

	// Check for context timeout
	if ctx.Err() != nil {
		return inventory.Finding{}, ctx.Err()
	}

	// Check legacy macOS cron
	if legacyIssues := d.checkMacOSLegacyCron(ctx, fsys); len(legacyIssues) > 0 {
		issues = append(issues, legacyIssues...)
	}

	if len(issues) == 0 {
		return inventory.Finding{}, nil
	}

	target := &inventory.GenericFindingTargetDetails{Extra: strings.Join(issues, "\n")}
	return d.findingForTarget(target), nil
}
