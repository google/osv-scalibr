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

// Package metadata defines a Metadata struct for CDX packages.
package metadata

import (
	"github.com/google/osv-scalibr/purl"
)

// Metadata holds parsing information for packages extracted from CDX files.
type Metadata struct {
	PURL         *purl.PackageURL
	CPEs         []string
	CDXLocations []string
}
