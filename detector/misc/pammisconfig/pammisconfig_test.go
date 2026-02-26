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

//go:build linux

package pammisconfig

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
)

func extractIssues(finding inventory.Finding) []string {
	var actualIssues []string
	if len(finding.GenericFindings) > 0 && finding.GenericFindings[0].Target != nil {
		extra := finding.GenericFindings[0].Target.Extra
		if extra != "" {
			actualIssues = strings.Split(extra, "\n")
		}
	}
	return actualIssues
}

func TestPAMPermitSufficient(t *testing.T) {
	tests := []struct {
		name       string
		files      map[string]string
		wantIssues []string
	}{
		{
			name: "pam_permit_as_sufficient_in_auth",
			files: map[string]string{
				"etc/pam.d/sshd": `# PAM configuration for sshd
auth sufficient pam_permit.so
auth required pam_unix.so`,
			},
			wantIssues: []string{
				"etc/pam.d/sshd:2: pam_permit.so with 'sufficient' control in auth stack - " +
					"this module always returns success, allowing password authentication to be bypassed",
			},
		},
		{
			name: "pam_permit_with_full_path",
			files: map[string]string{
				"etc/pam.d/system-auth": `# PAM system auth config
auth sufficient /lib/security/pam_permit.so
auth required pam_unix.so`,
			},
			wantIssues: []string{
				"etc/pam.d/system-auth:2: pam_permit.so with 'sufficient' control in auth stack - " +
					"this module always returns success, allowing password authentication to be bypassed",
			},
		},
		{
			name: "pam_permit_skip_next",
			files: map[string]string{
				"etc/pam.d/sshd": `# PAM configuration for sshd
auth [success=1 default=ignore] pam_permit.so
auth required pam_unix.so`,
			},
			wantIssues: []string{
				"etc/pam.d/sshd:2: pam_permit.so with '[success=1 default=ignore]' control in auth stack - " +
					"this module always returns success, allowing password authentication to be bypassed",
			},
		},
		{
			name: "pam_permit_optional_only_auth",
			files: map[string]string{
				"etc/pam.d/sshd": `# PAM configuration for sshd
auth optional pam_permit.so`,
			},
			wantIssues: []string{
				"etc/pam.d/sshd: pam_permit.so is the only auth module in this stack - optional controls can allow authentication without credential checks",
			},
		},
		{
			name: "pam_permit_as_optional_in_account",
			files: map[string]string{
				"etc/pam.d/sudo": `# PAM configuration for sudo
account optional pam_permit.so
account required pam_unix.so`,
			},
			// optional should not be flagged when other modules exist
			wantIssues: nil,
		},
		{
			name: "pam_permit_in_account_with_sufficient",
			files: map[string]string{
				"etc/pam.d/login": `# PAM configuration for login
account sufficient pam_permit.so
account required pam_unix.so`,
			},
			wantIssues: []string{
				"etc/pam.d/login:2: pam_permit.so with 'sufficient' control in account stack - " +
					"this module always returns success, allowing account checks (expiry, access restrictions) to be bypassed",
			},
		},
		{
			name: "pam_permit_as_required_is_safe",
			files: map[string]string{
				"etc/pam.d/login": `# PAM configuration for login
auth required pam_permit.so
auth required pam_unix.so`,
			},
			// required pam_permit.so is not a bypass since other modules still run
			wantIssues: nil,
		},
		{
			name: "pam_permit_in_session_is_safe",
			files: map[string]string{
				"etc/pam.d/common-session": `# PAM session config
session sufficient pam_permit.so`,
			},
			// session type is not an auth bypass risk
			wantIssues: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for path, content := range tt.files {
				fsys[path] = &fstest.MapFile{Data: []byte(content)}
			}

			d := &Detector{}
			finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

			if err != nil {
				t.Errorf("ScanFS() returned error: %v", err)
			}

			actualIssues := extractIssues(finding)

			if diff := cmp.Diff(tt.wantIssues, actualIssues); diff != "" {
				t.Errorf("PAM permit test mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPAMSucceedIfBroadConditions(t *testing.T) {
	tests := []struct {
		name       string
		files      map[string]string
		wantIssues []string
	}{
		{
			name: "pam_succeed_if_uid_comparison_sufficient",
			files: map[string]string{
				"etc/pam.d/sshd": `# PAM configuration for sshd
auth sufficient pam_succeed_if.so uid >= 1000
auth required pam_unix.so`,
			},
			wantIssues: []string{
				"etc/pam.d/sshd:2: pam_succeed_if.so with 'sufficient' control and broad condition 'uid >= 1000' " +
					"- users matching this condition can bypass password authentication",
			},
		},
		{
			name: "pam_succeed_if_user_not_root_sufficient",
			files: map[string]string{
				"etc/pam.d/sudo": `# PAM configuration for sudo
auth sufficient pam_succeed_if.so user != root
auth required pam_unix.so`,
			},
			wantIssues: []string{
				"etc/pam.d/sudo:2: pam_succeed_if.so with 'sufficient' control and broad condition 'user != root' " +
					"- users matching this condition can bypass password authentication",
			},
		},
		{
			name: "pam_succeed_if_as_required_is_safe",
			files: map[string]string{
				"etc/pam.d/login": `# PAM configuration for login
auth required pam_succeed_if.so uid >= 1000
auth required pam_unix.so`,
			},
			// required control means failure blocks auth, not a bypass
			wantIssues: nil,
		},
		{
			name: "pam_succeed_if_in_account_sufficient",
			files: map[string]string{
				"etc/pam.d/su": `# PAM configuration for su
account sufficient pam_succeed_if.so uid ingroup wheel
account required pam_unix.so`,
			},
			// ingroup conditions are not flagged to avoid false positives
			wantIssues: nil,
		},
		{
			name: "pam_succeed_if_skip_next_with_broad_condition",
			files: map[string]string{
				"etc/pam.d/sshd": `# PAM configuration for sshd
auth [success=1 default=ignore] pam_succeed_if.so uid >= 1000
auth required pam_unix.so`,
			},
			wantIssues: []string{
				"etc/pam.d/sshd:2: pam_succeed_if.so with '[success=1 default=ignore]' control and broad condition 'uid >= 1000' " +
					"- users matching this condition can bypass password authentication",
			},
		},
		{
			name: "pam_succeed_if_with_full_path",
			files: map[string]string{
				"etc/pam.d/login": `# PAM configuration for login
auth sufficient /lib64/security/pam_succeed_if.so uid >= 1000
auth required pam_unix.so`,
			},
			wantIssues: []string{
				"etc/pam.d/login:2: pam_succeed_if.so with 'sufficient' control and broad condition 'uid >= 1000' " +
					"- users matching this condition can bypass password authentication",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for path, content := range tt.files {
				fsys[path] = &fstest.MapFile{Data: []byte(content)}
			}

			d := &Detector{}
			finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

			if err != nil {
				t.Errorf("ScanFS() returned error: %v", err)
			}

			actualIssues := extractIssues(finding)

			if diff := cmp.Diff(tt.wantIssues, actualIssues); diff != "" {
				t.Errorf("PAM succeed_if test mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPAMNullokOption(t *testing.T) {
	tests := []struct {
		name       string
		files      map[string]string
		wantIssues []string
	}{
		{
			name: "nullok_on_pam_unix",
			files: map[string]string{
				"etc/pam.d/system-auth": `# PAM system auth config
auth required pam_unix.so nullok
auth required pam_deny.so`,
			},
			wantIssues: []string{
				"etc/pam.d/system-auth:2: 'nullok' option on pam_unix.so in auth stack - " +
					"allows accounts with empty passwords to authenticate, enabling unauthorized access",
			},
		},
		{
			name: "nullok_secure_on_pam_unix",
			files: map[string]string{
				"etc/pam.d/password-auth": `# PAM password auth config
auth required pam_unix.so nullok_secure try_first_pass
auth required pam_deny.so`,
			},
			wantIssues: []string{
				"etc/pam.d/password-auth:2: 'nullok_secure' option on pam_unix.so in auth stack - " +
					"allows accounts with empty passwords to authenticate, enabling unauthorized access",
			},
		},
		{
			name: "nullok_in_password_type_is_safe",
			files: map[string]string{
				"etc/pam.d/system-auth": `# PAM system auth config
password required pam_unix.so nullok sha512
auth required pam_unix.so`,
			},
			// nullok in password type (password changes) is less critical
			wantIssues: nil,
		},
		{
			name: "no_nullok_is_safe",
			files: map[string]string{
				"etc/pam.d/sshd": `# PAM sshd config
auth required pam_unix.so try_first_pass
auth required pam_deny.so`,
			},
			wantIssues: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for path, content := range tt.files {
				fsys[path] = &fstest.MapFile{Data: []byte(content)}
			}

			d := &Detector{}
			finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

			if err != nil {
				t.Errorf("ScanFS() returned error: %v", err)
			}

			actualIssues := extractIssues(finding)

			if diff := cmp.Diff(tt.wantIssues, actualIssues); diff != "" {
				t.Errorf("PAM nullok test mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPAMSecureConfigurations(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
	}{
		{
			name: "secure_sshd_config",
			files: map[string]string{
				"etc/pam.d/sshd": `# Secure PAM configuration for sshd
auth required pam_sepermit.so
auth substack password-auth
auth include postlogin
account required pam_nologin.so
account include password-auth
password include password-auth
session required pam_selinux.so close
session required pam_loginuid.so
session optional pam_keyinit.so force revoke
session include password-auth
session required pam_selinux.so open env_params
session optional pam_motd.so`,
			},
		},
		{
			name: "secure_sudo_config",
			files: map[string]string{
				"etc/pam.d/sudo": `# Secure PAM configuration for sudo
auth required pam_env.so
auth required pam_unix.so
account required pam_unix.so
session required pam_limits.so`,
			},
		},
		{
			name: "secure_login_config",
			files: map[string]string{
				"etc/pam.d/login": `# Secure PAM configuration for login
auth requisite pam_securetty.so
auth required pam_env.so
auth required pam_unix.so
account required pam_unix.so
password required pam_unix.so sha512 shadow
session required pam_limits.so
session required pam_unix.so`,
			},
		},
		{
			name: "comments_and_empty_lines",
			files: map[string]string{
				"etc/pam.d/test": `# This is a comment
# Another comment

# Empty line above
auth required pam_unix.so`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for path, content := range tt.files {
				fsys[path] = &fstest.MapFile{Data: []byte(content)}
			}

			d := &Detector{}
			finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

			if err != nil {
				t.Errorf("ScanFS() returned error: %v", err)
			}

			actualIssues := extractIssues(finding)

			if len(actualIssues) > 0 {
				t.Errorf("Expected no issues for secure config, got: %v", actualIssues)
			}
		})
	}
}

func TestPAMLegacyFormat(t *testing.T) {
	tests := []struct {
		name       string
		files      map[string]string
		wantIssues []string
	}{
		{
			name: "legacy_pam_conf_with_pam_permit",
			files: map[string]string{
				"etc/pam.conf": `# Legacy PAM configuration
sshd auth sufficient pam_permit.so
sshd auth required pam_unix.so`,
			},
			wantIssues: []string{
				"etc/pam.conf:2: pam_permit.so with 'sufficient' control in auth stack - " +
					"this module always returns success, allowing password authentication to be bypassed",
			},
		},
		{
			name: "legacy_pam_conf_secure",
			files: map[string]string{
				"etc/pam.conf": `# Legacy PAM configuration
sshd auth required pam_unix.so
sshd account required pam_unix.so`,
			},
			wantIssues: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for path, content := range tt.files {
				fsys[path] = &fstest.MapFile{Data: []byte(content)}
			}

			d := &Detector{}
			finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

			if err != nil {
				t.Errorf("ScanFS() returned error: %v", err)
			}

			actualIssues := extractIssues(finding)

			if diff := cmp.Diff(tt.wantIssues, actualIssues); diff != "" {
				t.Errorf("PAM legacy format test mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPAMMultipleIssues(t *testing.T) {
	files := map[string]string{
		"etc/pam.d/sshd": `# Misconfigured PAM
auth sufficient pam_permit.so
auth required pam_unix.so nullok`,
		"etc/pam.d/sudo": `# Another misconfigured PAM
auth sufficient pam_succeed_if.so uid >= 1000
auth required pam_unix.so`,
	}

	fsys := fstest.MapFS{}
	for path, content := range files {
		fsys[path] = &fstest.MapFile{Data: []byte(content)}
	}

	d := &Detector{}
	finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

	if err != nil {
		t.Errorf("ScanFS() returned error: %v", err)
	}

	actualIssues := extractIssues(finding)

	// Should find all issues across multiple files
	if len(actualIssues) < 3 {
		t.Errorf("Expected at least 3 issues, got %d: %v", len(actualIssues), actualIssues)
	}

	// Verify specific issues are present
	foundPermit := false
	foundNullok := false
	foundSucceedIf := false
	for _, issue := range actualIssues {
		if strings.Contains(issue, "pam_permit.so") {
			foundPermit = true
		}
		if strings.Contains(issue, "nullok") {
			foundNullok = true
		}
		if strings.Contains(issue, "pam_succeed_if.so") {
			foundSucceedIf = true
		}
	}

	if !foundPermit {
		t.Error("Expected pam_permit.so issue to be found")
	}
	if !foundNullok {
		t.Error("Expected nullok issue to be found")
	}
	if !foundSucceedIf {
		t.Error("Expected pam_succeed_if.so issue to be found")
	}
}

func TestPAMNoFiles(t *testing.T) {
	fsys := fstest.MapFS{}

	d := &Detector{}
	finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

	if err != nil {
		t.Errorf("ScanFS() returned error: %v", err)
	}

	if len(finding.GenericFindings) != 0 {
		t.Errorf("ScanFS() returned findings when no PAM files exist, got: %v", finding)
	}
}

func TestPAMLineContinuation(t *testing.T) {
	files := map[string]string{
		"etc/pam.d/test": `# PAM with line continuation
auth sufficient \
pam_permit.so
auth required pam_unix.so`,
	}

	fsys := fstest.MapFS{}
	for path, content := range files {
		fsys[path] = &fstest.MapFile{Data: []byte(content)}
	}

	d := &Detector{}
	finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

	if err != nil {
		t.Errorf("ScanFS() returned error: %v", err)
	}

	actualIssues := extractIssues(finding)

	if len(actualIssues) != 1 {
		t.Errorf("Expected 1 issue for line continuation, got %d: %v", len(actualIssues), actualIssues)
	}
}

func TestPAMOptionalModuleType(t *testing.T) {
	files := map[string]string{
		"etc/pam.d/test": `# PAM with optional module type prefix
-auth sufficient pam_permit.so
auth required pam_unix.so`,
	}

	fsys := fstest.MapFS{}
	for path, content := range files {
		fsys[path] = &fstest.MapFile{Data: []byte(content)}
	}

	d := &Detector{}
	finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

	if err != nil {
		t.Errorf("ScanFS() returned error: %v", err)
	}

	actualIssues := extractIssues(finding)

	// Should detect the issue even with the - prefix
	if len(actualIssues) != 1 {
		t.Errorf("Expected 1 issue for -auth type, got %d: %v", len(actualIssues), actualIssues)
	}
}

func TestDetectorInterface(t *testing.T) {
	d, _ := New(nil)

	if d.Name() != Name {
		t.Errorf("Name() = %q, want %q", d.Name(), Name)
	}

	finding := d.DetectedFinding()
	if len(finding.GenericFindings) != 1 {
		t.Errorf("DetectedFinding() expected 1 finding, got %d", len(finding.GenericFindings))
	}

	gf := finding.GenericFindings[0]
	if gf.Adv.Sev != inventory.SeverityCritical {
		t.Errorf("DetectedFinding() severity = %v, want Critical", gf.Adv.Sev)
	}

	if gf.Adv.ID.Publisher != "SCALIBR" {
		t.Errorf("DetectedFinding() publisher = %q, want SCALIBR", gf.Adv.ID.Publisher)
	}
}

func TestParsePAMLine(t *testing.T) {
	tests := []struct {
		name           string
		line           string
		isLegacyFormat bool
		wantEntry      *pamEntry
	}{
		{
			name:           "simple_auth_line",
			line:           "auth required pam_unix.so",
			isLegacyFormat: false,
			wantEntry: &pamEntry{
				moduleType: "auth",
				control:    "required",
				modulePath: "pam_unix.so",
				args:       nil,
			},
		},
		{
			name:           "auth_line_with_args",
			line:           "auth required pam_unix.so nullok try_first_pass",
			isLegacyFormat: false,
			wantEntry: &pamEntry{
				moduleType: "auth",
				control:    "required",
				modulePath: "pam_unix.so",
				args:       []string{"nullok", "try_first_pass"},
			},
		},
		{
			name:           "legacy_format_with_service",
			line:           "sshd auth required pam_unix.so",
			isLegacyFormat: true,
			wantEntry: &pamEntry{
				moduleType: "auth",
				control:    "required",
				modulePath: "pam_unix.so",
				args:       nil,
			},
		},
		{
			name:           "optional_type_prefix",
			line:           "-auth required pam_unix.so",
			isLegacyFormat: false,
			wantEntry: &pamEntry{
				moduleType: "auth",
				control:    "required",
				modulePath: "pam_unix.so",
				args:       nil,
			},
		},
		{
			name:           "too_few_fields",
			line:           "auth required",
			isLegacyFormat: false,
			wantEntry:      nil,
		},
		{
			name:           "invalid_type",
			line:           "invalid required pam_unix.so",
			isLegacyFormat: false,
			wantEntry:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsePAMLine(tt.line, tt.isLegacyFormat)

			if tt.wantEntry == nil {
				if got != nil {
					t.Errorf("parsePAMLine() = %v, want nil", got)
				}
				return
			}

			if got == nil {
				t.Errorf("parsePAMLine() = nil, want %v", tt.wantEntry)
				return
			}

			if got.moduleType != tt.wantEntry.moduleType {
				t.Errorf("moduleType = %q, want %q", got.moduleType, tt.wantEntry.moduleType)
			}
			if got.control != tt.wantEntry.control {
				t.Errorf("control = %q, want %q", got.control, tt.wantEntry.control)
			}
			if got.modulePath != tt.wantEntry.modulePath {
				t.Errorf("modulePath = %q, want %q", got.modulePath, tt.wantEntry.modulePath)
			}
			if diff := cmp.Diff(tt.wantEntry.args, got.args); diff != "" {
				t.Errorf("args mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPAMMalformedInputs(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
	}{
		{
			name: "empty_file",
			files: map[string]string{
				"etc/pam.d/empty": "",
			},
		},
		{
			name: "only_whitespace",
			files: map[string]string{
				"etc/pam.d/whitespace": "   \n\t\n   \n",
			},
		},
		{
			name: "only_comments",
			files: map[string]string{
				"etc/pam.d/comments": "# Comment 1\n# Comment 2\n# Comment 3",
			},
		},
		{
			name: "malformed_lines_ignored",
			files: map[string]string{
				"etc/pam.d/malformed": `this is not a valid pam line
auth
required pam_unix.so
auth required`,
			},
		},
		{
			name: "binary_garbage_ignored",
			files: map[string]string{
				"etc/pam.d/garbage": "\x00\x01\x02\x03\x04\x05",
			},
		},
		{
			name: "mixed_valid_and_invalid",
			files: map[string]string{
				"etc/pam.d/mixed": `garbage line
auth required pam_unix.so
another garbage
session required pam_limits.so`,
			},
		},
		{
			name: "extremely_long_line",
			files: map[string]string{
				"etc/pam.d/longline": "auth required pam_unix.so " + strings.Repeat("arg ", 1000),
			},
		},
		{
			name: "special_characters_in_args",
			files: map[string]string{
				"etc/pam.d/special": `auth required pam_unix.so key=value!@#$%^&*()`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for path, content := range tt.files {
				fsys[path] = &fstest.MapFile{Data: []byte(content)}
			}

			d := &Detector{}
			finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

			// Should not error on malformed input - graceful handling
			if err != nil {
				t.Errorf("ScanFS() returned error on malformed input: %v", err)
			}

			// Should not report false positives on malformed input
			actualIssues := extractIssues(finding)
			if len(actualIssues) > 0 {
				t.Errorf("Expected no issues for malformed input, got: %v", actualIssues)
			}
		})
	}
}
