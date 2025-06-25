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

// Package purl converts mixlock package details into a mixlock PackageURL.
package purl

import (
	"strings"

	"github.com/google/osv-scalibr/purl"
)

// MakePackageURL returns a package URL following the purl Hex spec with lowercase package names.
func MakePackageURL(name string, version string) *purl.PackageURL {
	return &purl.PackageURL{
		Type:    purl.TypeHex,
		Name:    strings.ToLower(name),
		Version: version,
	}
}
