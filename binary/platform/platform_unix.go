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

//go:build unix

// Package platform provides platform-specific functionality.
package platform

// SystemRoot returns the root directory of the system.
func SystemRoot() (string, error) {
	return "/", nil
}

// DefaultScanRoots returns the default list of directories to be scanned for Linux.
func DefaultScanRoots(allDrives bool) ([]string, error) {
	sysroot, err := SystemRoot()
	if err != nil {
		return nil, err
	}

	return []string{sysroot}, nil
}

// DefaultIgnoredDirectories returns the default list of directories to be ignored for Linux.
func DefaultIgnoredDirectories() ([]string, error) {
	return []string{"/dev", "/proc", "/sys"}, nil
}
