// Copyright 2026 Google LLC
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

// Package purl converts Composer package details into a Composer PackageURL.
package purl

import (
	"strings"

	"github.com/google/osv-scalibr/purl"
)

// MakePackageURL returns a package URL following the purl Composer spec:
//   - The namespace is the Composer vendor.
//   - The namespace and name must be lowercased.
//
// See: https://github.com/package-url/purl-spec/blob/main/types/composer-definition.json
func MakePackageURL(name string, version string) *purl.PackageURL {
	parts := strings.Split(name, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return &purl.PackageURL{
			Type:    purl.TypeComposer,
			Name:    strings.ToLower(name),
			Version: version,
		}
	}
	return &purl.PackageURL{
		Type:      purl.TypeComposer,
		Namespace: strings.ToLower(parts[0]),
		Name:      strings.ToLower(parts[1]),
		Version:   version,
	}
}
