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

// Package purl converts Go package details into a Go PackageURL.
package purl

import (
	"strings"

	"github.com/google/osv-scalibr/purl"
)

// MakePackageURL returns a package URL following the purl Golang spec:
//   - There is no default package repository: this is implied in the namespace using the go get
//     command conventions.
//   - The namespace and name must be lowercased.
//
// See: https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#golang
func MakePackageURL(name string, version string) *purl.PackageURL {
	name = strings.ToLower(name)
	namespace := ""
	nameParts := strings.Split(name, "/")
	if len(nameParts) > 1 {
		name = nameParts[len(nameParts)-1]
		namespace = strings.Join(nameParts[:len(nameParts)-1], "/")
	}
	return &purl.PackageURL{
		Type:      purl.TypeGolang,
		Name:      name,
		Namespace: namespace,
		Version:   version,
	}
}
