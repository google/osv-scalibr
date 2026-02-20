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

package cronjobprivesc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
)

// checkMacOSLaunchd checks macOS launchd plist files for security issues.
func checkMacOSLaunchd(ctx context.Context, fsys fs.FS) []string {
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
		if launchdIssues := checkMacOSLaunchdDirectory(ctx, fsys, dir); len(launchdIssues) > 0 {
			issues = append(issues, launchdIssues...)
		}
	}

	return issues
}

// checkMacOSLaunchdDirectory checks a directory containing launchd plist files.
func checkMacOSLaunchdDirectory(ctx context.Context, fsys fs.FS, dir string) []string {
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
			if plistIssues := checkMacOSLaunchdFile(fsys, plistPath); len(plistIssues) > 0 {
				issues = append(issues, plistIssues...)
			}
		}
	}

	return issues
}

// checkMacOSLaunchdFile checks a single launchd plist file.
func checkMacOSLaunchdFile(fsys fs.FS, filePath string) []string {
	var issues []string

	f, err := fsys.Open(filePath)
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
	isPrivileged := strings.Contains(filePath, "LaunchDaemons") ||
		strings.Contains(contentStr, "<key>UserName</key>") && strings.Contains(contentStr, "<string>root</string>")

	if isPrivileged {
		// Extract executable paths from ProgramArguments or Program
		if execIssues := analyzeMacOSLaunchdExecutables(fsys, filePath, contentStr); len(execIssues) > 0 {
			issues = append(issues, execIssues...)
		}
	}

	return issues
}

// analyzeMacOSLaunchdExecutables analyzes executable paths in a macOS launchd plist.
func analyzeMacOSLaunchdExecutables(fsys fs.FS, plistPath, content string) []string {
	var issues []string

	// Use regex to find string values after ProgramArguments or Program keys
	executableRegex := regexp.MustCompile(`<key>(?:Program|ProgramArguments)</key>\s*(?:<array>)?\s*<string>([^<]+)</string>`)
	matches := executableRegex.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			executable := strings.TrimSpace(match[1])

			// Check for relative paths
			// Attack scenario: Same as Unix cron - PATH manipulation allows attacker to hijack execution
			if !strings.HasPrefix(executable, "/") {
				issues = append(issues, fmt.Sprintf("%s: relative path '%s' in privileged launchd job - vulnerable to PATH manipulation attack", plistPath, executable))
				continue
			}

			// Check for execution from insecure directories
			dangerousPaths := []string{"/tmp/", "/var/tmp/", "/Users/Shared/"}
			for _, dangerousPath := range dangerousPaths {
				if strings.HasPrefix(executable, dangerousPath) {
					issues = append(issues, fmt.Sprintf("%s: execution from insecure directory '%s'", plistPath, executable))
				}
			}

			// Check all parent directories for world-writable permissions
			if dirIssues := checkPathHierarchyPermissions(fsys, executable); len(dirIssues) > 0 {
				for _, issue := range dirIssues {
					issues = append(issues, fmt.Sprintf("%s: %s", plistPath, issue))
				}
			}

			// Check file permissions
			if permIssues := checkExecutablePermissions(fsys, executable); len(permIssues) > 0 {
				for _, issue := range permIssues {
					issues = append(issues, fmt.Sprintf("%s: %s", plistPath, issue))
				}
			}
		}
	}

	return issues
}

// checkMacOSLegacyCron checks legacy cron configuration on macOS.
func checkMacOSLegacyCron(ctx context.Context, fsys fs.FS) []string {
	var issues []string

	// Check legacy crontab files
	cronPaths := []string{
		"usr/lib/cron/tabs/root",
		"private/var/cron/tabs/root",
	}

	for _, cronPath := range cronPaths {
		if ctx.Err() != nil {
			break
		}
		if cronIssues := checkCronFile(ctx, fsys, cronPath); len(cronIssues) > 0 {
			issues = append(issues, cronIssues...)
		}
	}

	return issues
}
