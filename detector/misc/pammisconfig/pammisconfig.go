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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/osv-scalibr/detector"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the detector.
	Name = "misc/pammisconfig"
)

// Detector is a SCALIBR Detector for PAM misconfiguration vulnerabilities.
type Detector struct{}

// New returns a new PAM misconfiguration detector.
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
func (Detector) DetectedFinding() inventory.Finding {
	return findingForTarget(nil)
}

func findingForTarget(target *inventory.GenericFindingTargetDetails) inventory.Finding {
	return inventory.Finding{GenericFindings: []*inventory.GenericFinding{{
		Adv: &inventory.GenericFindingAdvisory{
			ID: &inventory.AdvisoryID{
				Publisher: "SCALIBR",
				Reference: "pam-authentication-bypass",
			},
			Title: "PAM Configuration Allows Authentication Bypass",
			Description: "Misconfigured PAM (Pluggable Authentication Modules) stack permits " +
				"unauthorized login. This can occur when permissive modules like pam_permit.so " +
				"are used as 'sufficient' in the auth stack, when pam_succeed_if.so bypasses " +
				"authentication with broad conditions, or when nullok allows empty passwords. " +
				"Attackers can exploit these misconfigurations to gain unauthorized access " +
				"to SSH, sudo, console login, and other PAM-protected services.",
			Recommendation: "Review and secure PAM configurations in /etc/pam.d/: " +
				"1) Remove or restrict pam_permit.so usage in auth stacks, " +
				"2) Avoid pam_succeed_if.so as 'sufficient' with broad conditions, " +
				"3) Remove 'nullok' option from authentication modules to prevent empty password login, " +
				"4) Ensure proper 'required' modules like pam_unix.so are present. " +
				"Test changes with pamtester before applying to production.",
			Sev: inventory.SeverityCritical,
		},
		Target: target,
	}}}
}

// PAM control flags that can cause authentication bypass when misconfigured.
// Reference: http://www.linux-pam.org/Linux-PAM-html/sag-configuration-file.html
var (
	// bypassControls are control flags that, when used with permissive modules,
	// can short-circuit authentication and bypass password validation.
	bypassControls = map[string]bool{
		"sufficient": true, // Success here stops auth stack if previous required modules passed
	}

	// pam_succeed_if condition patterns that are too broad and dangerous.
	// These conditions can match large groups of users, bypassing auth.
	// Example: "uid >= 1000" matches all normal users (UID >= 1000 on most systems).
	broadConditionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\buid\s*(>=|>|!=)\s*\d+\b`), // uid comparisons, excluding equality
		regexp.MustCompile(`\bgid\s*(>=|>|!=)\s*\d+\b`), // gid comparisons, excluding equality
		regexp.MustCompile(`\buser\s*!=\s*root\b`),      // user is not root (all other users)
		regexp.MustCompile(`\buid\s*!=\s*0\b`),          // uid is not 0 (all non-root)
		regexp.MustCompile(`\buid\s*(>=|>)\s*1000\b`),   // common broad user ranges
		regexp.MustCompile(`\buid\s*(>=|>)\s*\d{4,}\b`), // large uid ranges
		regexp.MustCompile(`\buser\s*!=\s*\w+\b`),       // exclude a single user (broad)
		regexp.MustCompile(`\bshell\s*!=\s*\S+\b`),      // exclude a single shell
		regexp.MustCompile(`\buid\s*>=\s*0\b`),          // matches all users
		regexp.MustCompile(`\buid\s*>\s*0\b`),           // matches all non-root users
	}
)

// ScanFS starts the scan from a pseudo-filesystem.
func (d Detector) ScanFS(ctx context.Context, fsys fs.FS, px *packageindex.PackageIndex) (inventory.Finding, error) {
	var issues []string

	// Check for context timeout
	if ctx.Err() != nil {
		return inventory.Finding{}, ctx.Err()
	}

	// Check PAM configuration files
	if pamIssues := checkPAMConfigs(ctx, fsys); len(pamIssues) > 0 {
		issues = append(issues, pamIssues...)
	}

	if len(issues) == 0 {
		return inventory.Finding{}, nil
	}

	target := &inventory.GenericFindingTargetDetails{Extra: strings.Join(issues, "\n")}
	return findingForTarget(target), nil
}

// checkPAMConfigs checks PAM configuration files for security issues.
func checkPAMConfigs(ctx context.Context, fsys fs.FS) []string {
	var issues []string

	// Check /etc/pam.d/ directory for service-specific configs
	if pamDirIssues := checkPAMDirectory(ctx, fsys, "etc/pam.d"); len(pamDirIssues) > 0 {
		issues = append(issues, pamDirIssues...)
	}

	// Check /etc/pam.conf (legacy single-file config, less common)
	if pamConfIssues := checkPAMFile(ctx, fsys, "etc/pam.conf", true); len(pamConfIssues) > 0 {
		issues = append(issues, pamConfIssues...)
	}

	return issues
}

// checkPAMDirectory checks all files in /etc/pam.d/.
func checkPAMDirectory(ctx context.Context, fsys fs.FS, dir string) []string {
	var issues []string

	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return issues
		}
		return issues
	}

	for _, entry := range entries {
		if ctx.Err() != nil {
			break
		}
		if entry.IsDir() {
			continue
		}
		filePath := dir + "/" + entry.Name()
		if fileIssues := checkPAMFile(ctx, fsys, filePath, false); len(fileIssues) > 0 {
			issues = append(issues, fileIssues...)
		}
	}

	return issues
}

// checkPAMFile checks a specific PAM configuration file for security issues.
// isLegacyFormat indicates if this is /etc/pam.conf (includes service name field).
func checkPAMFile(ctx context.Context, fsys fs.FS, filePath string, isLegacyFormat bool) []string {
	var issues []string

	f, err := fsys.Open(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return issues
		}
		return issues
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	var authEntries []pamEntry
	for scanner.Scan() {
		if ctx.Err() != nil {
			break
		}
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle line continuations (backslash at end)
		for strings.HasSuffix(line, "\\") && scanner.Scan() {
			line = strings.TrimSuffix(line, "\\") + " " + strings.TrimSpace(scanner.Text())
			lineNum++
		}

		entry := parsePAMLine(line, isLegacyFormat)
		if entry != nil && entry.moduleType == "auth" {
			authEntries = append(authEntries, *entry)
		}

		if lineIssues := analyzePAMLine(filePath, lineNum, line, isLegacyFormat); len(lineIssues) > 0 {
			issues = append(issues, lineIssues...)
		}
	}

	if optionalIssues := checkOptionalOnlyAuth(filePath, authEntries); len(optionalIssues) > 0 {
		issues = append(issues, optionalIssues...)
	}

	return issues
}

// pamEntry represents a parsed PAM configuration line.
type pamEntry struct {
	moduleType string   // auth, account, password, session
	control    string   // required, sufficient, optional, etc.
	modulePath string   // e.g., pam_unix.so, pam_permit.so
	args       []string // module arguments
}

// analyzePAMLine analyzes a single PAM configuration line for security issues.
func analyzePAMLine(filePath string, lineNum int, line string, isLegacyFormat bool) []string {
	var issues []string

	entry := parsePAMLine(line, isLegacyFormat)
	if entry == nil {
		return issues
	}

	// Only check auth and account types for authentication bypass
	// - auth: handles user authentication (password verification)
	// - account: handles account validation (expiry, access restrictions)
	if entry.moduleType != "auth" && entry.moduleType != "account" {
		return issues
	}

	// Check 1: pam_permit.so in auth/account stack
	// pam_permit.so ALWAYS returns success, so using it with bypass controls
	// means any user can authenticate without a valid password.
	// Reference: https://serverfault.com/questions/890012/pam-accepting-any-password-for-valid-users
	if isModule(entry.modulePath, "pam_permit.so") {
		control := parseControlEffect(entry.control)
		if control.isSufficientLike || control.skipNext > 0 {
			issues = append(issues, fmt.Sprintf(
				"%s:%d: pam_permit.so with '%s' control in %s stack - this module always "+
					"returns success, allowing %s to be bypassed",
				filePath, lineNum, entry.control, entry.moduleType, bypassImpact(entry.moduleType)))
		}
	}

	// Check 2: pam_succeed_if.so with broad conditions as sufficient
	// pam_succeed_if.so can match broad user groups (e.g., uid >= 1000),
	// and when combined with 'sufficient', those users bypass further auth checks.
	// Reference: https://unix.stackexchange.com/a/767197
	if isModule(entry.modulePath, "pam_succeed_if.so") {
		control := parseControlEffect(entry.control)
		if control.isSufficientLike || control.skipNext > 0 {
			condition := extractPAMSucceedIfCondition(entry.args)
			if condition != "" && isBroadPAMSucceedIfCondition(condition) {
				issues = append(issues, fmt.Sprintf(
					"%s:%d: pam_succeed_if.so with '%s' control and broad condition '%s' "+
						"- users matching this condition can bypass %s",
					filePath, lineNum, entry.control, condition, bypassImpact(entry.moduleType)))
			}
		}
	}

	// Check 3: nullok option on authentication modules
	// The nullok option allows accounts with empty/null passwords to authenticate.
	// This is a security risk as it permits passwordless login.
	// Reference: https://static.open-scap.org/ssg-guides/ssg-rhel8-guide-rht-ccp.html
	if entry.moduleType == "auth" {
		for _, arg := range entry.args {
			if arg == "nullok" || arg == "nullok_secure" {
				issues = append(issues, fmt.Sprintf(
					"%s:%d: '%s' option on %s in auth stack - allows accounts with "+
						"empty passwords to authenticate, enabling unauthorized access",
					filePath, lineNum, arg, entry.modulePath))
				break
			}
		}
	}

	return issues
}

func extractPAMSucceedIfCondition(args []string) string {
	if len(args) == 0 {
		return ""
	}

	// Remove common options that are not predicates.
	filtered := make([]string, 0, len(args))
	for _, arg := range args {
		if isPAMSucceedIfOption(arg) {
			continue
		}
		filtered = append(filtered, arg)
	}

	return strings.Join(filtered, " ")
}

func isPAMSucceedIfOption(arg string) bool {
	switch arg {
	case "quiet", "quiet_fail", "quiet_success", "use_uid", "debug", "onerr=fail", "onerr=succeed":
		return true
	default:
		return strings.HasPrefix(arg, "quiet=") || strings.HasPrefix(arg, "onerr=")
	}
}

func isBroadPAMSucceedIfCondition(condition string) bool {
	if condition == "" {
		return false
	}

	for _, pattern := range broadConditionPatterns {
		if pattern.MatchString(condition) {
			return true
		}
	}

	return false
}

type controlEffect struct {
	isSufficientLike bool
	skipNext         int
	isOptionalOnly   bool
}

func parseControlEffect(control string) controlEffect {
	control = strings.ToLower(control)

	if bypassControls[control] {
		return controlEffect{isSufficientLike: true}
	}
	if control == "optional" {
		return controlEffect{isOptionalOnly: true}
	}

	if !strings.HasPrefix(control, "[") || !strings.HasSuffix(control, "]") {
		return controlEffect{}
	}

	inner := strings.TrimSuffix(strings.TrimPrefix(control, "["), "]")
	for _, token := range strings.Fields(inner) {
		parts := strings.SplitN(token, "=", 2)
		if len(parts) != 2 || parts[0] != "success" {
			continue
		}
		action := parts[1]
		switch action {
		case "ok", "done":
			return controlEffect{isSufficientLike: true}
		default:
			if skip := parseSkipCount(action); skip > 0 {
				return controlEffect{skipNext: skip}
			}
		}
	}

	return controlEffect{}
}

func parseSkipCount(action string) int {
	if action == "" {
		return 0
	}
	for _, ch := range action {
		if ch < '0' || ch > '9' {
			return 0
		}
	}

	count, err := strconv.Atoi(action)
	if err != nil || count < 1 {
		return 0
	}

	return count
}

func isModule(modulePath, expected string) bool {
	clean := path.Base(modulePath)
	return clean == expected
}

func bypassImpact(moduleType string) string {
	if moduleType == "account" {
		return "account checks (expiry, access restrictions)"
	}
	return "password authentication"
}

func checkOptionalOnlyAuth(filePath string, entries []pamEntry) []string {
	if len(entries) == 0 {
		return nil
	}

	var hasEffectiveNonOptional bool
	var hasPermitOptional bool
	for _, entry := range entries {
		control := parseControlEffect(entry.control)
		if !control.isOptionalOnly {
			hasEffectiveNonOptional = true
		}
		if isModule(entry.modulePath, "pam_permit.so") && control.isOptionalOnly {
			hasPermitOptional = true
		}
	}

	if hasPermitOptional && !hasEffectiveNonOptional {
		return []string{
			fmt.Sprintf("%s: pam_permit.so is the only auth module in this stack - optional controls can allow authentication without credential checks", filePath),
		}
	}

	return nil
}

// parsePAMLine parses a PAM configuration line into its components.
// PAM line format: [service] type control module-path [module-arguments]
// In /etc/pam.d/, service is derived from filename (no service field).
// In /etc/pam.conf, service is the first field.
func parsePAMLine(line string, isLegacyFormat bool) *pamEntry {
	fields := strings.Fields(line)

	minFields := 3 // type control module
	if isLegacyFormat {
		minFields = 4 // service type control module
	}

	if len(fields) < minFields {
		return nil
	}

	var entry pamEntry
	offset := 0
	if isLegacyFormat {
		offset = 1 // skip service field
	}

	entry.moduleType = strings.ToLower(fields[offset])
	entry.control = strings.ToLower(fields[offset+1])
	entry.modulePath = fields[offset+2]

	if len(fields) > offset+3 {
		entry.args = fields[offset+3:]
	}

	// Validate module type
	validTypes := map[string]bool{
		"auth": true, "account": true, "password": true, "session": true,
		// Also handle -type prefix (e.g., -auth) which means optional
		"-auth": true, "-account": true, "-password": true, "-session": true,
	}
	if !validTypes[entry.moduleType] {
		return nil
	}

	// Normalize -type to type (the dash means optional/silent fail)
	entry.moduleType = strings.TrimPrefix(entry.moduleType, "-")

	return &entry
}
