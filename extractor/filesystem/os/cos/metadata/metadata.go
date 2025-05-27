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

// Package metadata defines a metadata struct for COS packages.
package metadata

import "github.com/google/osv-scalibr/log"

// Metadata holds parsing information for a COS package.
type Metadata struct {
	Name          string
	Version       string
	Category      string
	OSVersion     string
	OSVersionID   string
	EbuildVersion string
}

// ToDistro extracts the OS distro from the metadata.
func (m *Metadata) ToDistro() string {
	if m.OSVersionID != "" {
		return "cos-" + m.OSVersionID
	}

	if m.OSVersion != "" {
		log.Warnf("VERSION_ID not set in os-release, fallback to VERSION")
		return "cos-" + m.OSVersion
	}
	log.Errorf("VERSION and VERSION_ID not set in os-release")
	return ""
}
