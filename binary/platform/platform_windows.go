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

//go:build windows

package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/osv-scalibr/plugin"
	"golang.org/x/sys/windows"
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

func retrieveAllDrives() ([]string, error) {
	// first determine the required size of the buffer
	size, err := windows.GetLogicalDriveStrings(0, nil)
	if err != nil {
		return nil, err
	}

	// perform the actual syscall
	buf := make([]uint16, size)
	n, err := windows.GetLogicalDriveStrings(size, &buf[0])
	if err != nil {
		return nil, err
	}

	var drives []string
	var drive string
	var i uint32

	// parse the output (null separated strings)
	for ; i < n; i++ {
		if buf[i] == 0 {
			drives = append(drives, drive)
			drive = ""
			continue
		}

		drive += fmt.Sprintf("%c", buf[i])
	}

	return drives, nil
}

// DefaultScanRoots returns the default list of directories to be scanned for Windows.
func DefaultScanRoots(allDrives bool) ([]string, error) {
	systemDrive, err := SystemRoot()
	if err != nil {
		return nil, err
	}

	scanRoots := []string{systemDrive}

	if allDrives {
		drives, err := retrieveAllDrives()
		if err != nil {
			return nil, err
		}

		// add all drives to the scan roots, but we remove the system drive as it's already in the list
		for _, drive := range drives {
			if drive != systemDrive {
				scanRoots = append(scanRoots, drive)
			}
		}
	}

	return scanRoots, nil
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

// OS returns the OS the SCALIBR binary was build on.
func OS() plugin.OS {
	return plugin.OSWindows
}
