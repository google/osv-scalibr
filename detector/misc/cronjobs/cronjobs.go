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

// Package cronjobs implements a detector for misconfigured cron jobs and scheduled tasks that could lead to privilege escalation.
package cronjobs

import (
	"bufio"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
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
	Name = "cronjobs"
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
func (Detector) Requirements() *plugin.Capabilities { return &plugin.Capabilities{OS: plugin.OSAny} }

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

	target := &inventory.GenericFindingTargetDetails{Extra: strings.Join(issues, "; ")}
	return d.findingForTarget(target), nil
}

// checkLinuxCronJobs checks Linux cron job configurations for security issues.
func (d Detector) checkLinuxCronJobs(ctx context.Context, fsys fs.FS) []string {
	var issues []string

	// Check /etc/crontab
	if cronIssues := d.checkCronFile(ctx, fsys, "etc/crontab"); len(cronIssues) > 0 {
		issues = append(issues, cronIssues...)
	}

	// Check /etc/cron.d/*
	if cronDirIssues := d.checkCronDirectory(ctx, fsys, "etc/cron.d"); len(cronDirIssues) > 0 {
		issues = append(issues, cronDirIssues...)
	}

	// Check periodic cron directories
	cronDirs := []string{"etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly"}
	for _, dir := range cronDirs {
		if ctx.Err() != nil {
			break
		}
		if cronDirIssues := d.checkCronScriptDirectory(ctx, fsys, dir); len(cronDirIssues) > 0 {
			issues = append(issues, cronDirIssues...)
		}
	}

	// Check user crontabs
	if userCronIssues := d.checkUserCrontabs(ctx, fsys, "var/spool/cron"); len(userCronIssues) > 0 {
		issues = append(issues, userCronIssues...)
	}

	return issues
}

// checkCronFile checks a specific cron file for security issues.
func (d Detector) checkCronFile(ctx context.Context, fsys fs.FS, path string) []string {
	var issues []string

	f, err := fsys.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return issues
		}
		return issues
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
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

		if cronIssues := d.analyzeCronLine(fsys, path, lineNum, line); len(cronIssues) > 0 {
			issues = append(issues, cronIssues...)
		}
	}

	return issues
}

// checkCronDirectory checks all files in a cron directory.
func (d Detector) checkCronDirectory(ctx context.Context, fsys fs.FS, dir string) []string {
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
		if !entry.IsDir() {
			path := dir + "/" + entry.Name()
			if cronIssues := d.checkCronFile(ctx, fsys, path); len(cronIssues) > 0 {
				issues = append(issues, cronIssues...)
			}
		}
	}

	return issues
}

// checkCronScriptDirectory checks executable scripts in cron periodic directories.
func (d Detector) checkCronScriptDirectory(ctx context.Context, fsys fs.FS, dir string) []string {
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
		if !entry.IsDir() {
			scriptPath := dir + "/" + entry.Name()
			if scriptIssues := d.checkExecutablePermissions(fsys, scriptPath); len(scriptIssues) > 0 {
				issues = append(issues, scriptIssues...)
			}
		}
	}

	return issues
}

// checkUserCrontabs checks user crontab files in /var/spool/cron.
func (d Detector) checkUserCrontabs(ctx context.Context, fsys fs.FS, dir string) []string {
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
		if !entry.IsDir() {
			path := dir + "/" + entry.Name()
			if entry.Name() == "root" {
				// This is root's crontab, check it
				if cronIssues := d.checkCronFile(ctx, fsys, path); len(cronIssues) > 0 {
					issues = append(issues, cronIssues...)
				}
			}
		}
	}

	return issues
}

// analyzeCronLine analyzes a single cron line for security issues.
func (d Detector) analyzeCronLine(fsys fs.FS, filePath string, lineNum int, line string) []string {
	var issues []string

	// Parse cron line format: minute hour day month weekday [user] command
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return issues
	}

	// Check if this is a user-specified format (system crontab)
	var user string
	var command string
	if len(fields) >= 7 {
		// System crontab format includes user field
		user = fields[5]
		command = strings.Join(fields[6:], " ")
	} else {
		// User crontab format (no user field)
		user = "root" // Assume root for system files
		command = strings.Join(fields[5:], " ")
	}

	// Only check jobs running as root or privileged users
	if user == "root" || user == "0" {
		if cmdIssues := d.analyzeCommand(fsys, filePath, lineNum, command); len(cmdIssues) > 0 {
			issues = append(issues, cmdIssues...)
		}
	}

	return issues
}

// analyzeCommand analyzes a command for security issues.
func (d Detector) analyzeCommand(fsys fs.FS, filePath string, lineNum int, command string) []string {
	var issues []string

	// Extract the first part of the command (the executable)
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return issues
	}

	executable := parts[0]

	// Check for relative paths
	if !strings.HasPrefix(executable, "/") {
		issues = append(issues, fmt.Sprintf("%s:%d: relative path '%s' in privileged cron job", filePath, lineNum, executable))
		return issues
	}

	// Check for execution in world-writable directories
	dangerousPaths := []string{"/tmp/", "/var/tmp/", "/dev/shm/"}
	for _, dangerousPath := range dangerousPaths {
		if strings.HasPrefix(executable, dangerousPath) {
			issues = append(issues, fmt.Sprintf("%s:%d: execution from world-writable directory '%s'", filePath, lineNum, executable))
		}
	}

	// Check file permissions of the executable
	if permIssues := d.checkExecutablePermissions(fsys, executable); len(permIssues) > 0 {
		for _, issue := range permIssues {
			issues = append(issues, fmt.Sprintf("%s:%d: %s", filePath, lineNum, issue))
		}
	}

	return issues
}

// checkExecutablePermissions checks if an executable has secure permissions.
func (d Detector) checkExecutablePermissions(fsys fs.FS, path string) []string {
	var issues []string

	f, err := fsys.Open(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			issues = append(issues, fmt.Sprintf("cannot access '%s': %v", path, err))
		}
		return issues
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return issues
	}

	perms := info.Mode().Perm()

	// Check for world-writable permissions
	if perms&0002 != 0 {
		issues = append(issues, fmt.Sprintf("'%s' is world-writable (permissions: %03o)", path, perms))
	}

	// Check for group-writable permissions (less critical but worth noting)
	if perms&0020 != 0 {
		issues = append(issues, fmt.Sprintf("'%s' is group-writable (permissions: %03o)", path, perms))
	}

	// Check ownership if we can get it
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if stat.Uid != 0 {
			issues = append(issues, fmt.Sprintf("'%s' is not owned by root (uid: %d)", path, stat.Uid))
		}
	}

	return issues
}

// WindowsTaskDefinition represents the structure of a Windows scheduled task XML.
type WindowsTaskDefinition struct {
	XMLName    xml.Name              `xml:"Task"`
	Triggers   WindowsTaskTriggers   `xml:"Triggers"`
	Principals WindowsTaskPrincipals `xml:"Principals"`
	Actions    WindowsTaskActions    `xml:"Actions"`
}

// WindowsTaskTriggers represents task trigger configurations in Windows Task Scheduler XML.
type WindowsTaskTriggers struct {
	BootTrigger     []WindowsTaskTrigger `xml:"BootTrigger"`
	CalendarTrigger []WindowsTaskTrigger `xml:"CalendarTrigger"`
	IdleTrigger     []WindowsTaskTrigger `xml:"IdleTrigger"`
	LogonTrigger    []WindowsTaskTrigger `xml:"LogonTrigger"`
	TimeTrigger     []WindowsTaskTrigger `xml:"TimeTrigger"`
}

// WindowsTaskTrigger represents a single task trigger in Windows Task Scheduler XML.
type WindowsTaskTrigger struct {
	Enabled string `xml:"Enabled"`
}

// WindowsTaskPrincipals represents task security principals in Windows Task Scheduler XML.
type WindowsTaskPrincipals struct {
	Principal []WindowsTaskPrincipal `xml:"Principal"`
}

// WindowsTaskPrincipal represents a single security principal in Windows Task Scheduler XML.
type WindowsTaskPrincipal struct {
	RunLevel string `xml:"RunLevel"`
	UserID   string `xml:"UserId"`
}

// WindowsTaskActions represents task actions in Windows Task Scheduler XML.
type WindowsTaskActions struct {
	Exec []WindowsTaskExec `xml:"Exec"`
}

// WindowsTaskExec represents an executable action in Windows Task Scheduler XML.
type WindowsTaskExec struct {
	Command   string `xml:"Command"`
	Arguments string `xml:"Arguments"`
}

// checkWindowsTaskScheduler checks Windows scheduled tasks for security issues.
func (d Detector) checkWindowsTaskScheduler(ctx context.Context, fsys fs.FS) []string {
	var issues []string

	// Check tasks in the system tasks directory
	if taskIssues := d.checkWindowsTaskDirectory(ctx, fsys, "Windows/System32/Tasks"); len(taskIssues) > 0 {
		issues = append(issues, taskIssues...)
	}

	return issues
}

// checkWindowsTaskDirectory recursively checks Windows task directories.
func (d Detector) checkWindowsTaskDirectory(ctx context.Context, fsys fs.FS, dir string) []string {
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

		entryPath := dir + "/" + entry.Name()
		if entry.IsDir() {
			// Recursively check subdirectories
			if subdirIssues := d.checkWindowsTaskDirectory(ctx, fsys, entryPath); len(subdirIssues) > 0 {
				issues = append(issues, subdirIssues...)
			}
		} else {
			// Check individual task files
			if taskIssues := d.checkWindowsTaskFile(ctx, fsys, entryPath); len(taskIssues) > 0 {
				issues = append(issues, taskIssues...)
			}
		}
	}

	return issues
}

// checkWindowsTaskFile checks a Windows task XML file.
func (d Detector) checkWindowsTaskFile(ctx context.Context, fsys fs.FS, path string) []string {
	var issues []string

	f, err := fsys.Open(path)
	if err != nil {
		return issues
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		return issues
	}

	var task WindowsTaskDefinition
	if err := xml.Unmarshal(content, &task); err != nil {
		// Not a valid XML task file
		return issues
	}

	// Check if task runs with elevated privileges
	isElevated := false
	isSystemUser := false
	for _, principal := range task.Principals.Principal {
		if principal.RunLevel == "HighestAvailable" || principal.RunLevel == "RequireAdministrator" {
			isElevated = true
		}
		if strings.ToUpper(principal.UserID) == "SYSTEM" ||
			strings.ToUpper(principal.UserID) == "NT AUTHORITY\\SYSTEM" ||
			strings.Contains(strings.ToUpper(principal.UserID), "ADMINISTRATOR") {
			isSystemUser = true
		}
	}

	if isElevated || isSystemUser {
		// Check the commands being executed
		for _, exec := range task.Actions.Exec {
			if ctx.Err() != nil {
				break
			}
			if execIssues := d.analyzeWindowsCommand(fsys, path, exec.Command); len(execIssues) > 0 {
				issues = append(issues, execIssues...)
			}
		}
	}

	return issues
}

// analyzeWindowsCommand analyzes a Windows scheduled task command.
func (d Detector) analyzeWindowsCommand(fsys fs.FS, taskPath, command string) []string {
	var issues []string

	// Check for execution from writable system directories
	dangerousPaths := []string{
		"C:\\Windows\\Temp\\",
		"C:\\Temp\\",
		"C:\\Users\\Public\\",
		"%TEMP%\\",
		"%TMP%\\",
	}

	upperCommand := strings.ToUpper(command)
	for _, dangerousPath := range dangerousPaths {
		if strings.HasPrefix(upperCommand, strings.ToUpper(dangerousPath)) {
			issues = append(issues, fmt.Sprintf("%s: execution from writable directory '%s'", taskPath, command))
		}
	}

	// Check for relative paths
	if !strings.Contains(command, ":\\") && !strings.HasPrefix(command, "%") {
		issues = append(issues, fmt.Sprintf("%s: relative path '%s' in privileged scheduled task", taskPath, command))
	}

	// Try to check file permissions if the path exists
	cleanPath := strings.TrimPrefix(command, "\"")
	cleanPath = strings.TrimSuffix(cleanPath, "\"")

	// Convert Windows paths to filesystem paths (remove drive letters for abstract FS)
	if len(cleanPath) >= 3 && cleanPath[1] == ':' {
		cleanPath = cleanPath[3:] // Remove "C:\" part
	}
	cleanPath = strings.ReplaceAll(cleanPath, "\\", "/")

	if permIssues := d.checkExecutablePermissions(fsys, cleanPath); len(permIssues) > 0 {
		for _, issue := range permIssues {
			issues = append(issues, fmt.Sprintf("%s: %s", taskPath, issue))
		}
	}

	return issues
}

// MacOSLaunchd represents a macOS launchd plist structure.
type MacOSLaunchd struct {
	Label                string            `plist:"Label"`
	ProgramArguments     []string          `plist:"ProgramArguments"`
	Program              string            `plist:"Program"`
	UserName             string            `plist:"UserName"`
	GroupName            string            `plist:"GroupName"`
	RunAtLoad            bool              `plist:"RunAtLoad"`
	KeepAlive            bool              `plist:"KeepAlive"`
	StartOnMount         bool              `plist:"StartOnMount"`
	LaunchOnlyOnce       bool              `plist:"LaunchOnlyOnce"`
	EnvironmentVariables map[string]string `plist:"EnvironmentVariables"`
}

// checkMacOSLaunchd checks macOS launchd plist files for security issues.
func (d Detector) checkMacOSLaunchd(ctx context.Context, fsys fs.FS) []string {
	var issues []string

	// Check system-wide launch daemons and agents
	launchdDirs := []string{
		"System/Library/LaunchDaemons",
		"Library/LaunchDaemons",
		"Library/LaunchAgents",
	}

	for _, dir := range launchdDirs {
		if ctx.Err() != nil {
			break
		}
		if launchdIssues := d.checkMacOSLaunchdDirectory(ctx, fsys, dir); len(launchdIssues) > 0 {
			issues = append(issues, launchdIssues...)
		}
	}

	return issues
}

// checkMacOSLaunchdDirectory checks a directory containing launchd plist files.
func (d Detector) checkMacOSLaunchdDirectory(ctx context.Context, fsys fs.FS, dir string) []string {
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
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".plist") {
			plistPath := dir + "/" + entry.Name()
			if plistIssues := d.checkMacOSLaunchdFile(fsys, plistPath); len(plistIssues) > 0 {
				issues = append(issues, plistIssues...)
			}
		}
	}

	return issues
}

// checkMacOSLaunchdFile checks a single launchd plist file.
func (d Detector) checkMacOSLaunchdFile(fsys fs.FS, path string) []string {
	var issues []string

	f, err := fsys.Open(path)
	if err != nil {
		return issues
	}
	defer f.Close()

	// For simplicity, we'll parse the plist as plain text to look for key patterns
	// A full plist parser would be more robust but adds complexity
	content, err := io.ReadAll(f)
	if err != nil {
		return issues
	}

	contentStr := string(content)

	// Check if this is a daemon/agent running as root or with elevated privileges
	isPrivileged := strings.Contains(path, "LaunchDaemons") ||
		strings.Contains(contentStr, "<key>UserName</key>") && strings.Contains(contentStr, "<string>root</string>")

	if isPrivileged {
		// Extract executable paths from ProgramArguments or Program
		if execIssues := d.analyzeMacOSLaunchdExecutables(fsys, path, contentStr); len(execIssues) > 0 {
			issues = append(issues, execIssues...)
		}
	}

	return issues
}

// analyzeMacOSLaunchdExecutables analyzes executable paths in a macOS launchd plist.
func (d Detector) analyzeMacOSLaunchdExecutables(fsys fs.FS, plistPath, content string) []string {
	var issues []string

	// Use regex to find string values after ProgramArguments or Program keys
	executableRegex := regexp.MustCompile(`<key>(?:Program|ProgramArguments)</key>\s*(?:<array>)?\s*<string>([^<]+)</string>`)
	matches := executableRegex.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			executable := strings.TrimSpace(match[1])

			// Check for relative paths
			if !strings.HasPrefix(executable, "/") {
				issues = append(issues, fmt.Sprintf("%s: relative path '%s' in privileged launchd job", plistPath, executable))
				continue
			}

			// Check for execution from insecure directories
			dangerousPaths := []string{"/tmp/", "/var/tmp/", "/Users/Shared/"}
			for _, dangerousPath := range dangerousPaths {
				if strings.HasPrefix(executable, dangerousPath) {
					issues = append(issues, fmt.Sprintf("%s: execution from insecure directory '%s'", plistPath, executable))
				}
			}

			// Check file permissions
			if permIssues := d.checkExecutablePermissions(fsys, executable); len(permIssues) > 0 {
				for _, issue := range permIssues {
					issues = append(issues, fmt.Sprintf("%s: %s", plistPath, issue))
				}
			}
		}
	}

	return issues
}

// checkMacOSLegacyCron checks legacy cron configuration on macOS.
func (d Detector) checkMacOSLegacyCron(ctx context.Context, fsys fs.FS) []string {
	var issues []string

	// Check legacy crontab files
	cronPaths := []string{
		"usr/lib/cron/tabs/root",
		"private/var/cron/tabs/root",
	}

	for _, path := range cronPaths {
		if ctx.Err() != nil {
			break
		}
		if cronIssues := d.checkCronFile(ctx, fsys, path); len(cronIssues) > 0 {
			issues = append(issues, cronIssues...)
		}
	}

	return issues
}
