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

// Package detector provides the interface for security-related detection plugins.
package detector

import (
	"context"

	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
)

// Detector is the interface for a security detector plugin, used to scan for security findings
// such as vulnerabilities.
type Detector interface {
	plugin.Plugin
	// RequiredExtractors returns a list of Extractors that need to be enabled for this
	// Detector to run.
	RequiredExtractors() []string
	// DetectedFinding returns generic information about the finding identified by the detector.
	// Generic means the finding do not contain any information specific to the target or extras.
	// E.g. no paths (locations), no IP addresses or any other information that could identify the
	// target.
	DetectedFinding() inventory.Finding
	// Scan performs the security scan, considering scanRoot to be the root directory.
	// Implementations may use PackageIndex to check if a relevant software package is installed and
	// terminate early if it's not.
	Scan(c context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error)
}
