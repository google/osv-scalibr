// Copyright 2024 Google LLC
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

//go:build windows

package platform

import (
	"errors"
	"os"
	"path/filepath"
)

var (
	errSystemDriveNotSet = errors.New("SystemDrive environment variable not set")
)

// SystemRoot returns the root directory of the system.
func SystemRoot() (string, error) {
	if os.Getenv("SystemDrive") == "" {
		return "", errSystemDriveNotSet
	}

	return os.Getenv("SystemDrive") + string(os.PathSeparator), nil
}

// DefaultScanRoots returns the default list of directories to be scanned for Windows.
func DefaultScanRoots() ([]string, error) {
	systemDrive, err := SystemRoot()
	if err != nil {
		return nil, err
	}

	return []string{systemDrive}, nil
}

// DefaultIgnoredDirectories returns the default list of directories to be ignored for Windows.
func DefaultIgnoredDirectories() ([]string, error) {
	systemDrive, err := SystemRoot()
	if err != nil {
		return nil, err
	}

	windir := filepath.Join(systemDrive, "Windows")
	return []string{windir}, nil
}
