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

//go:build linux || darwin

// Package etcpasswdpermissions implements a detector for the "Ensure permissions on /etc/passwd- are configured" CIS check.
package etcpasswdpermissions

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"github.com/google/osv-scalibr/detector"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the detector.
	Name = "cis/generic-linux/etcpasswdpermissions"
)

// Detector is a SCALIBR Detector for the CIS check "Ensure permissions on /etc/passwd- are configured"
// from the CIS Distribution Independent Linux benchmarks.
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
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) ([]*detector.Finding, error) {
	return d.ScanFS(ctx, scanRoot.FS, px)
}

// ScanFS starts the scan from a pseudo-filesystem.
func (Detector) ScanFS(ctx context.Context, fs fs.FS, px *packageindex.PackageIndex) ([]*detector.Finding, error) {
	f, err := fs.Open("etc/passwd")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// File doesn't exist, check not applicable.
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	problems := ""
	if info.Mode().Perm() != 0644 {
		problems = fmt.Sprintf("file permissions %03o, expected 644\n", info.Mode().Perm())
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("failed to get file ownership info")
	}

	if stat.Uid != 0 {
		problems += fmt.Sprintf("file owner %d, expected 0/root\n", stat.Uid)
	}
	if stat.Gid != 0 {
		problems += fmt.Sprintf("file group %d, expected 0/root\n", stat.Gid)
	}

	if len(problems) == 0 {
		return nil, nil
	}
	title := "Ensure permissions on /etc/passwd are configured"
	description := "The /etc/passwd file contains user account information that " +
		"is used by many system utilities and therefore must be readable for these " +
		"utilities to operate."
	recommendation := "Run the following command to set permissions on /etc/passwd :\n" +
		"# chown root:root /etc/passwd\n" +
		"# chmod 644 /etc/passwd"
	return []*detector.Finding{{
		Adv: &detector.Advisory{
			ID: &detector.AdvisoryID{
				Publisher: "CIS",
				Reference: "etc-passwd-permissions",
			},
			Type:           detector.TypeCISFinding,
			Title:          title,
			Description:    description,
			Recommendation: recommendation,
			Sev:            &detector.Severity{Severity: detector.SeverityMinimal},
		},
		Target: &detector.TargetDetails{Location: []string{"/etc/passwd"}},
		Extra:  problems,
	}}, nil
}
