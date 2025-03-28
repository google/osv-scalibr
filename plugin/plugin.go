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

// Package plugin collects the common code used by extractor and detector plugins.
package plugin

import (
	"fmt"
	"strings"
)

// OS is the OS the scanner is running on, or a specific OS type a Plugin needs to be run on.
type OS int

// OS values
const (
	OSAny     OS = iota
	OSLinux   OS = iota
	OSWindows OS = iota
	OSMac     OS = iota
	// OSUnix is used only when specifying Plugin requirements.
	// Specifies that the plugin needs to be run either on Linux or Mac.
	OSUnix OS = iota
)

// Network is the network access of the scanner or the network
// requirements of a plugin.
type Network int

// Network values
const (
	// NetworkAny is used only when specifying Plugin requirements. Specifies
	// that the plugin doesn't care whether the scanner has network access or not.
	NetworkAny     Network = iota
	NetworkOffline Network = iota
	NetworkOnline  Network = iota
)

// Capabilities lists capabilities that the scanning environment provides for the plugins.
// A plugin can't be enabled if it has more requirements than what the scanning environment provides.
type Capabilities struct {
	// A specific OS type a Plugin needs to be run on.
	OS OS
	// Whether network access is provided.
	Network Network
	// Whether the scanned artifacts can be access through direct filesystem calls.
	// True on hosts where the scan target is mounted onto the host's filesystem directly.
	// In these cases the plugin can open direct file paths with e.g. os.Open(path).
	// False if the artifact is not on the host but accessed through an abstract FS interface
	// (e.g. scanning a remote container image). In these cases the plugin must use the FS interface
	// to access the filesystem.
	DirectFS bool
	// Whether the scanner is scanning the real running system it's on. Examples where this is not the case:
	// * We're scanning a virtual filesystem unrelated to the host where SCALIBR is running.
	// * We're scanning a real filesystem of e.g. a container image that's mounted somewhere on disk.
	RunningSystem bool
}

// Plugin is the part of the plugin interface that's shared between extractors and detectors.
type Plugin interface {
	// A unique name used to identify this plugin.
	Name() string
	// Plugin version, should get bumped whenever major changes are made.
	Version() int
	// Requirements about the scanning environment, e.g. "needs to have network access".
	Requirements() *Capabilities
}

// LINT.IfChange

// Status contains the status and version of the plugins that ran.
type Status struct {
	Name    string
	Version int
	Status  *ScanStatus
}

// ScanStatus is the status of a scan run. In case the scan fails, FailureReason contains details.
type ScanStatus struct {
	Status        ScanStatusEnum
	FailureReason string
}

// ScanStatusEnum is the enum for the scan status.
type ScanStatusEnum int

// ScanStatusEnum values.
const (
	ScanStatusUnspecified ScanStatusEnum = iota
	ScanStatusSucceeded
	ScanStatusPartiallySucceeded
	ScanStatusFailed
)

// LINT.ThenChange(/binary/proto/scan_result.proto)

// ValidateRequirements checks that the specified  scanning capabilities satisfy
// the requirements of a given plugin.
func ValidateRequirements(p Plugin, capabs *Capabilities) error {
	errs := []string{}
	if p.Requirements().OS == OSUnix {
		if capabs.OS != OSLinux && capabs.OS != OSMac {
			errs = append(errs, "needs to run on Unix system but scan environment is non-Unix")
		}
	} else if p.Requirements().OS != OSAny && p.Requirements().OS != capabs.OS {
		errs = append(errs, "needs to run on a different OS than that of the scan environment")
	}
	if p.Requirements().Network != NetworkAny && p.Requirements().Network != capabs.Network {
		if capabs.Network == NetworkOffline {
			errs = append(errs, "needs network access but scan environment doesn't provide it")
		} else {
			errs = append(errs, "should only run offline but the scan environment provides network access")
		}
	}
	if p.Requirements().DirectFS && !capabs.DirectFS {
		errs = append(errs, "needs direct filesystem access but scan environment doesn't provide it")
	}
	if p.Requirements().RunningSystem && !capabs.RunningSystem {
		errs = append(errs, "scanner isn't scanning the host it's run from directly")
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("plugin %s can't be enabled: %s", p.Name(), strings.Join(errs, ", "))
}

// StatusFromErr returns a successful or failed plugin scan status for a given plugin based on an error.
func StatusFromErr(p Plugin, partial bool, err error) *Status {
	status := &ScanStatus{}
	if err == nil {
		status.Status = ScanStatusSucceeded
	} else {
		if partial {
			status.Status = ScanStatusPartiallySucceeded
		} else {
			status.Status = ScanStatusFailed
		}
		status.FailureReason = err.Error()
	}
	return &Status{
		Name:    p.Name(),
		Version: p.Version(),
		Status:  status,
	}
}

// String returns a string representation of the scan status.
func (s *ScanStatus) String() string {
	switch s.Status {
	case ScanStatusSucceeded:
		return "SUCCEEDED"
	case ScanStatusPartiallySucceeded:
		return "PARTIALLY_SUCCEEDED"
	case ScanStatusFailed:
		return "FAILED: " + s.FailureReason
	}
	return "UNSPECIFIED"
}
