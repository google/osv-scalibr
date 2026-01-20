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

package cronjobprivesc

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// checkExecutablePermissions checks if an executable has secure permissions.
func checkExecutablePermissions(fsys fs.FS, filePath string) []string {
	var issues []string

	f, err := fsys.Open(filePath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			issues = append(issues, fmt.Sprintf("cannot access '%s': %v", filePath, err))
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
		issues = append(issues, fmt.Sprintf("'%s' is world-writable (permissions: %03o)", filePath, perms))
	}

	// Check for group-writable permissions (less critical but worth noting)
	if perms&0020 != 0 {
		issues = append(issues, fmt.Sprintf("'%s' is group-writable (permissions: %03o)", filePath, perms))
	}

	// Check ownership - syscall.Stat_t is available on Unix systems
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if stat.Uid != 0 {
			issues = append(issues, fmt.Sprintf("'%s' is not owned by root (uid: %d)", filePath, stat.Uid))
		}
	}

	return issues
}
