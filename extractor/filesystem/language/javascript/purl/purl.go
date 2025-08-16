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

// Package purl converts NPM package details into an NPM PackageURL.
package purl

import (
	"strconv"

	javascriptmeta "github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson/metadata"
	"github.com/google/osv-scalibr/purl"
)

// MakePackageURL returns a package URL following the purl NPM spec with lowercase package names.
func MakePackageURL(name string, version string, metadata any) *purl.PackageURL {
	q := make(map[string]string)
	if m, ok := metadata.(*javascriptmeta.JavascriptPackageJSONMetadata); ok && m.FromNPMRepository {
		q["from-npm-repository"] = strconv.FormatBool(true)
	}
	var qualifiers purl.Qualifiers
	if len(q) > 0 {
		qualifiers = purl.QualifiersFromMap(q)
	}
	return &purl.PackageURL{
		Type:       purl.TypeNPM,
		Name:       name,
		Version:    version,
		Qualifiers: qualifiers,
	}
}
