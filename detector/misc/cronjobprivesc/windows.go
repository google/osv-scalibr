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

package cronjobprivesc

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
)

var (
	// windowsAbsolutePathRegex matches Windows absolute paths like C:\ or D:\
	windowsAbsolutePathRegex = regexp.MustCompile(`^[A-Z]:\\`)
)

// WindowsTaskDefinition represents the structure of a Windows scheduled task XML.
type WindowsTaskDefinition struct {
	Principals WindowsTaskPrincipals `xml:"Principals"`
	Actions    WindowsTaskActions    `xml:"Actions"`
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
	Command string `xml:"Command"`
}

// checkWindowsTaskScheduler checks Windows scheduled tasks for security issues.
func checkWindowsTaskScheduler(ctx context.Context, fsys fs.FS) []string {
	var issues []string

	// Check tasks in the system tasks directory
	if taskIssues := checkWindowsTaskDirectory(ctx, fsys, "Windows/System32/Tasks"); len(taskIssues) > 0 {
		issues = append(issues, taskIssues...)
	}

	return issues
}

// checkWindowsTaskDirectory recursively checks Windows task directories.
func checkWindowsTaskDirectory(ctx context.Context, fsys fs.FS, dir string) []string {
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
			if subdirIssues := checkWindowsTaskDirectory(ctx, fsys, entryPath); len(subdirIssues) > 0 {
				issues = append(issues, subdirIssues...)
			}
		} else {
			// Check individual task files
			if taskIssues := checkWindowsTaskFile(ctx, fsys, entryPath); len(taskIssues) > 0 {
				issues = append(issues, taskIssues...)
			}
		}
	}

	return issues
}

// checkWindowsTaskFile checks a Windows task XML file.
func checkWindowsTaskFile(ctx context.Context, fsys fs.FS, filePath string) []string {
	var issues []string

	f, err := fsys.Open(filePath)
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
		userID := strings.ToUpper(principal.UserID)
		if userID == "SYSTEM" ||
			userID == "NT AUTHORITY\\SYSTEM" ||
			strings.Contains(userID, "ADMINISTRATOR") {
			isSystemUser = true
		}
	}

	if isElevated || isSystemUser {
		// Check the commands being executed
		for _, exec := range task.Actions.Exec {
			if ctx.Err() != nil {
				break
			}
			if execIssues := analyzeWindowsCommand(fsys, filePath, exec.Command); len(execIssues) > 0 {
				issues = append(issues, execIssues...)
			}
		}
	}

	return issues
}

// analyzeWindowsCommand analyzes a Windows scheduled task command.
func analyzeWindowsCommand(fsys fs.FS, taskPath, command string) []string {
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

	// Check for relative paths - must start with drive letter (e.g., C:\) or environment variable
	// Attack scenario: Relative paths in Windows scheduled tasks can be exploited via DLL hijacking
	// or PATH manipulation, similar to Unix cron jobs.
	if !windowsAbsolutePathRegex.MatchString(strings.ToUpper(command)) && !strings.HasPrefix(command, "%") {
		issues = append(issues, fmt.Sprintf("%s: relative path '%s' in privileged scheduled task - vulnerable to PATH manipulation or DLL hijacking attack", taskPath, command))
	}

	// Try to check file permissions if the path exists
	cleanPath := strings.TrimPrefix(command, "\"")
	cleanPath = strings.TrimSuffix(cleanPath, "\"")

	// Convert Windows paths to filesystem paths (remove drive letters for abstract FS)
	if len(cleanPath) >= 3 && cleanPath[1] == ':' {
		cleanPath = cleanPath[3:] // Remove "C:\" part
	}
	cleanPath = strings.ReplaceAll(cleanPath, "\\", "/")

	if permIssues := checkExecutablePermissions(fsys, cleanPath); len(permIssues) > 0 {
		for _, issue := range permIssues {
			issues = append(issues, fmt.Sprintf("%s: %s", taskPath, issue))
		}
	}

	return issues
}
