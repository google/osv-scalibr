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

// Package pypipurl converts an inventory to a PyPI type PackageURL.
// TODO(#173, b/365452344): Replace with purl.New() which will contain mapping of all ecosystems
package pypipurl

import (
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
)

var specialCharRunFinder = regexp.MustCompile("[-_.]+")

// MakePackageURL returns a package URL following the purl PyPI spec:
// - Name is lowercased
// - Replaces all runs of ` _ . - ` with -
//
// See: https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#pypi
// And: https://peps.python.org/pep-0503/#normalized-names
//
// This function does *not* handle package names with invalid characters, and will
// return them as is.
func MakePackageURL(i *extractor.Inventory) *purl.PackageURL {
	normalizedName := specialCharRunFinder.ReplaceAllLiteralString(strings.ToLower(i.Name), "-")
	return &purl.PackageURL{
		Type:    purl.TypePyPi,
		Name:    normalizedName,
		Version: i.Version,
	}
}
