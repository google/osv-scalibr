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

// Package plugin collects the common code used by extractor and detector plugins.
package plugin

import "fmt"

// Plugin is the part of the plugin interface that's shared between extractors and detectors.
type Plugin interface {
	// A unique name used to identify this plugin.
	Name() string
	// Plugin version, should get bumped whenever major changes are made.
	Version() int
}

// LINT.IfChange

// Status contains the status and version of the inventory+vuln plugins that ran.
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

// LINT.ThenChange(binary/proto/scan_result.proto)

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
		return fmt.Sprintf("FAILED: %s", s.FailureReason)
	}
	return "UNSPECIFIED"
}
