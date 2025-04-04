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

// Package inventory stores the scan result types SCALIBR can return.
package inventory

import (
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor"
)

// Inventory stores the artifacts (e.g. software packages, security findings)
// that a scan found.
type Inventory struct {
	Packages []*extractor.Package
	Findings []*detector.Finding
}

// Append adds one or more inventories to the current one.
func (i *Inventory) Append(other ...Inventory) {
	for _, o := range other {
		i.Packages = append(i.Packages, o.Packages...)
		i.Findings = append(i.Findings, o.Findings...)
	}
}

// IsEmpty returns true if there are no packages, findings, etc. in this Inventory.
func (i Inventory) IsEmpty() bool {
	return len(i.Packages) == 0 && len(i.Findings) == 0
}
