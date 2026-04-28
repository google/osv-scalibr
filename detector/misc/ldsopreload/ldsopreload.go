// Copyright 2026 Google LLC
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

// Package ldsopreload detects insecure /etc/ld.so.preload permissions
// that can lead to privilege escalation via dynamic linker hijacking.
package ldsopreload

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/google/osv-scalibr/detector"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name of the detector.
	Name = "misc/ldsopreload"

	// preloadPath is the virtual-FS relative path to ld.so.preload.
	preloadPath = "etc/ld.so.preload"

	oGroupWrite = 0o020
	oOtherWrite = 0o002
)

var errNotDir = errors.New("not a directory")

// Detector is a SCALIBR Detector for insecure /etc/ld.so.preload
// permissions that could allow dynamic linker preload hijacking.
type Detector struct{}

// New returns a new ld.so.preload detector.
func New(_ *cpb.PluginConfig) (detector.Detector, error) {
	return &Detector{}, nil
}

// Name of the detector.
func (Detector) Name() string { return Name }

// Version of the detector.
func (Detector) Version() int { return 0 }

// RequiredExtractors returns an empty list as there are no dependencies.
func (Detector) RequiredExtractors() []string { return []string{} }

// Requirements of the Detector.
func (Detector) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{OS: plugin.OSLinux}
}

// Scan starts the scan.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	return d.ScanFS(ctx, scanRoot.FS, px)
}

// DetectedFinding returns generic vulnerability information about what
// is detected.
func (Detector) DetectedFinding() inventory.Finding {
	return findingForTarget(nil)
}

func findingForTarget(target *inventory.GenericFindingTargetDetails) inventory.Finding {
	return inventory.Finding{GenericFindings: []*inventory.GenericFinding{{
		Adv: &inventory.GenericFindingAdvisory{
			ID: &inventory.AdvisoryID{
				Publisher: "SCALIBR",
				Reference: "ld-so-preload-hijack",
			},
			Title: "Insecure /etc/ld.so.preload Permissions " +
				"Enable Privilege Escalation",
			Description: "/etc/ld.so.preload is read by the glibc " +
				"dynamic linker (ld.so) before every dynamically " +
				"linked program executes. If this file or its parent " +
				"directories are writable by non-root users, an " +
				"attacker can inject a malicious shared library path, " +
				"achieving code execution in any privileged process " +
				"including SUID binaries and root services. " +
				"Reference: https://attack.mitre.org/techniques/T1574/006/",
			Recommendation: "Secure /etc/ld.so.preload and its parent " +
				"directories: " +
				"1) Set ownership to root:root " +
				"(chown root:root /etc/ld.so.preload), " +
				"2) Set file permissions to 0644 or stricter " +
				"(chmod 644 /etc/ld.so.preload), " +
				"3) Ensure /etc is not writable by non-root users, " +
				"4) Remove /etc/ld.so.preload entirely if not needed.",
			Sev: inventory.SeverityHigh,
		},
		Target: target,
	}}}
}

// ScanFS starts the scan from a pseudo-filesystem.
func (d Detector) ScanFS(ctx context.Context, fsys fs.FS, px *packageindex.PackageIndex) (inventory.Finding, error) {
	if ctx.Err() != nil {
		return inventory.Finding{}, ctx.Err()
	}

	var issues []string

	fileIssues, exists, err := checkFilePermissions(fsys, preloadPath)
	if err != nil {
		return inventory.Finding{}, err
	}
	if exists {
		issues = append(issues, fileIssues...)
	}

	if ctx.Err() != nil {
		return inventory.Finding{}, ctx.Err()
	}

	dirIssues, err := checkParentDirPermissions(fsys)
	if err != nil {
		return inventory.Finding{}, err
	}
	if len(dirIssues) > 0 {
		issues = append(issues, dirIssues...)
	}

	if len(issues) == 0 {
		return inventory.Finding{}, nil
	}

	target := &inventory.GenericFindingTargetDetails{
		Extra: strings.Join(issues, "\n"),
	}
	return findingForTarget(target), nil
}

// checkFilePermissions checks the permissions of /etc/ld.so.preload.
// The returned bool indicates whether the file exists.
func checkFilePermissions(fsys fs.FS, path string) ([]string, bool, error) {
	info, err := fs.Stat(fsys, path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("stat %q: %w", path, err)
	}

	perms := info.Mode().Perm()

	issues := []string{}

	if perms&oOtherWrite != 0 {
		issues = append(issues, fmt.Sprintf(
			"/etc/ld.so.preload is world-writable (permissions: %03o)"+
				" - any local user can inject a malicious shared library"+
				" that will be loaded into every dynamically linked process",
			perms))
	}

	if perms&oGroupWrite != 0 {
		issues = append(issues, fmt.Sprintf(
			"/etc/ld.so.preload is group-writable (permissions: %03o)"+
				" - members of the owning group can inject a malicious"+
				" shared library for preload hijacking",
			perms))
	}

	ownershipIssues, err := ownershipIssues("/etc/ld.so.preload", info)
	if err != nil {
		return nil, true, err
	}
	issues = append(issues, ownershipIssues...)

	return issues, true, nil
}

// parentDirs lists the ancestor directories of /etc/ld.so.preload
// that we check (in virtual-FS relative path form).
var parentDirs = []string{".", "etc"}

// checkParentDirPermissions checks whether any parent directory in the
// path to /etc/ld.so.preload is writable by non-root users.
// A writable parent directory allows an attacker to replace or create
// the preload file even if the file itself has secure permissions.
func checkParentDirPermissions(fsys fs.FS) ([]string, error) {
	var issues []string

	for _, dir := range parentDirs {
		info, err := dirInfo(fsys, dir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}

		perms := info.Mode().Perm()
		displayDir := displayDirPath(dir)
		if perms&oOtherWrite != 0 {
			issues = append(issues, fmt.Sprintf(
				"parent directory %s is world-writable"+
					" (permissions: %03o) - an attacker can"+
					" create or replace ld.so.preload to hijack"+
					" the dynamic linker",
				displayDir, perms))
		}

		if perms&oGroupWrite != 0 {
			issues = append(issues, fmt.Sprintf(
				"parent directory %s is group-writable"+
					" (permissions: %03o) - group members can"+
					" create or replace ld.so.preload to hijack"+
					" the dynamic linker",
				displayDir, perms))
		}

		ownershipIssues, err := ownershipIssues(
			"parent directory "+displayDir, info)
		if err != nil {
			return nil, err
		}
		issues = append(issues, ownershipIssues...)
	}

	return issues, nil
}

func displayDirPath(dir string) string {
	if dir == "." || dir == "" {
		return "/"
	}
	return "/" + dir
}

// dirInfo returns the FileInfo of a directory.
func dirInfo(fsys fs.FS, path string) (fs.FileInfo, error) {
	info, err := fs.Stat(fsys, path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("%q: %w", path, errNotDir)
	}

	return info, nil
}
