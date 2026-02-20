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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
)

// checkLinuxCronJobs checks Linux cron job configurations for security issues.
func checkLinuxCronJobs(ctx context.Context, fsys fs.FS) []string {
	var issues []string

	// Check /etc/crontab
	if cronIssues := checkCronFile(ctx, fsys, "etc/crontab"); len(cronIssues) > 0 {
		issues = append(issues, cronIssues...)
	}

	// Check /etc/cron.d/*
	if cronDirIssues := checkCronDirectory(ctx, fsys, "etc/cron.d"); len(cronDirIssues) > 0 {
		issues = append(issues, cronDirIssues...)
	}

	// Check periodic cron directories
	cronDirs := []string{"etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly"}
	for _, dir := range cronDirs {
		if ctx.Err() != nil {
			break
		}
		if cronDirIssues := checkCronScriptDirectory(ctx, fsys, dir); len(cronDirIssues) > 0 {
			issues = append(issues, cronDirIssues...)
		}
	}

	// Check user crontabs
	if userCronIssues := checkUserCrontabs(ctx, fsys, "var/spool/cron"); len(userCronIssues) > 0 {
		issues = append(issues, userCronIssues...)
	}

	return issues
}

// checkCronFile checks a specific cron file for security issues.
func checkCronFile(ctx context.Context, fsys fs.FS, filePath string) []string {
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

		if cronIssues := analyzeCronLine(fsys, filePath, lineNum, line); len(cronIssues) > 0 {
			issues = append(issues, cronIssues...)
		}
	}

	return issues
}

// checkCronDirectory checks all files in a cron directory.
func checkCronDirectory(ctx context.Context, fsys fs.FS, dir string) []string {
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
			filePath := dir + "/" + entry.Name()
			if cronIssues := checkCronFile(ctx, fsys, filePath); len(cronIssues) > 0 {
				issues = append(issues, cronIssues...)
			}
		}
	}

	return issues
}

// checkCronScriptDirectory checks executable scripts in cron periodic directories.
func checkCronScriptDirectory(ctx context.Context, fsys fs.FS, dir string) []string {
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
			if scriptIssues := checkExecutablePermissions(fsys, scriptPath); len(scriptIssues) > 0 {
				issues = append(issues, scriptIssues...)
			}
		}
	}

	return issues
}

// checkUserCrontabs checks user crontab files in /var/spool/cron.
func checkUserCrontabs(ctx context.Context, fsys fs.FS, dir string) []string {
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
			filePath := dir + "/" + entry.Name()
			if entry.Name() == "root" {
				// This is root's crontab, check it
				if cronIssues := checkCronFile(ctx, fsys, filePath); len(cronIssues) > 0 {
					issues = append(issues, cronIssues...)
				}
			}
		}
	}

	return issues
}

// analyzeCronLine analyzes a single cron line for security issues.
func analyzeCronLine(fsys fs.FS, filePath string, lineNum int, line string) []string {
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
		if cmdIssues := analyzeCommand(fsys, filePath, lineNum, command); len(cmdIssues) > 0 {
			issues = append(issues, cmdIssues...)
		}
	}

	return issues
}

// analyzeCommand analyzes a command for security issues.
func analyzeCommand(fsys fs.FS, filePath string, lineNum int, command string) []string {
	var issues []string

	// Extract the first part of the command (the executable)
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return issues
	}

	executable := parts[0]

	// Check for relative paths - vulnerable to PATH manipulation attacks
	// Attack scenario: If a cron job uses a relative path like "backup.sh" instead of "/usr/local/bin/backup.sh",
	// an attacker who can modify the PATH environment variable or place a malicious script earlier in the PATH
	// can hijack the execution. Since cron jobs run with root privileges, this leads to privilege escalation.
	// Reference: https://github.com/google/osv-scalibr/issues/1262#issue-3386484717
	if !strings.HasPrefix(executable, "/") {
		issues = append(issues, fmt.Sprintf("%s:%d: relative path '%s' in privileged cron job - vulnerable to PATH manipulation attack where attacker places malicious executable earlier in PATH", filePath, lineNum, executable))
		return issues
	}

	// Check if any parent directory in the path is world-writable with execute permission
	// Per Unix permissions: to access a file, all parent directories must have execute permission.
	// If any parent directory is world-writable AND has execute permission for others,
	// an attacker could potentially manipulate the path (e.g., via symlinks or directory replacement).
	if dirIssues := checkPathHierarchyPermissions(fsys, executable); len(dirIssues) > 0 {
		for _, issue := range dirIssues {
			issues = append(issues, fmt.Sprintf("%s:%d: %s", filePath, lineNum, issue))
		}
	}

	// Check file permissions of the executable
	if permIssues := checkExecutablePermissions(fsys, executable); len(permIssues) > 0 {
		for _, issue := range permIssues {
			issues = append(issues, fmt.Sprintf("%s:%d: %s", filePath, lineNum, issue))
		}
	}

	return issues
}

const (
	oWrite = 0o002
	oExec  = 0o001
)

// checkPathHierarchyPermissions checks all parent directories in a path for world-writable permissions.
// A world-writable directory is only exploitable if ALL its parent directories are world-executable.
// Per Unix permissions: to access a directory, all parent directories must have execute permission.
func checkPathHierarchyPermissions(fsys fs.FS, executablePath string) []string {
	var issues []string

	// Build list of all parent directories from executable up to root
	var parentDirs []string
	currentPath := executablePath
	for {
		parentDir := path.Dir(currentPath)
		if parentDir == currentPath || parentDir == "." || parentDir == "/" {
			break
		}

		fsPath := strings.TrimPrefix(parentDir, "/")
		if fsPath == "" {
			break
		}

		parentDirs = append(parentDirs, fsPath)
		currentPath = parentDir
	}

	permsList := make([]fs.FileMode, len(parentDirs))
	permsOk := make([]bool, len(parentDirs))
	for i, dirPath := range parentDirs {
		perms, err := getDirectoryPermissions(fsys, dirPath)
		if err != nil {
			continue
		}
		permsList[i] = perms
		permsOk[i] = true
	}

	// Precompute whether all parents above each directory are world-executable.
	parentsExecutable := make([]bool, len(parentDirs))
	if len(parentDirs) > 0 {
		last := len(parentDirs) - 1
		parentsExecutable[last] = permsOk[last] && (permsList[last]&oExec != 0)
		for i := len(parentDirs) - 2; i >= 0; i-- {
			parentsExecutable[i] = permsOk[i] && (permsList[i]&oExec != 0) && parentsExecutable[i+1]
		}
	}

	// Check each directory: if it's world-writable, verify all parents are world-executable
	for i, dirPath := range parentDirs {
		if !permsOk[i] {
			continue
		}

		isWorldWritable := permsList[i]&oWrite != 0
		isWorldExecutable := permsList[i]&oExec != 0
		if !isWorldWritable || !isWorldExecutable {
			continue
		}

		allParentsExecutable := true
		if i < len(parentDirs)-1 {
			allParentsExecutable = parentsExecutable[i+1]
		}

		// Only flag as vulnerable if all parents are world-executable
		if allParentsExecutable {
			issues = append(issues, fmt.Sprintf("parent directory '%s' of '%s' is world-writable (permissions: %03o) and all parent directories are world-executable - attackers can manipulate path", dirPath, executablePath, permsList[i]))
		}
	}

	return issues
}

// getDirectoryPermissions returns the permissions of a directory.
func getDirectoryPermissions(fsys fs.FS, dirPath string) (fs.FileMode, error) {
	f, err := fsys.Open(dirPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return 0, err
	}

	return info.Mode().Perm(), nil
}
