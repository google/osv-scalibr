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

// Package purl converts Windows application package details into a PackageURL.
package purl

import (
	winmeta "github.com/google/osv-scalibr/extractor/standalone/windows/common/metadata"
	"github.com/google/osv-scalibr/purl"
)

// MakePackageURL returns a package URL for Windows applications.
func MakePackageURL(name string, version string, metadata any) *purl.PackageURL {
	var qualifiers purl.Qualifiers
	if m, ok := metadata.(*winmeta.OSVersion); ok {
		qualifiers = purl.QualifiersFromMap(map[string]string{
			purl.BuildNumber: m.FullVersion,
		})
	}
	return &purl.PackageURL{
		Type:       purl.TypeGeneric,
		Namespace:  "microsoft",
		Name:       name,
		Version:    version,
		Qualifiers: qualifiers,
	}
}
