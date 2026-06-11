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

// Package purl converts NPM package details into an NPM PackageURL.
package purl

import (
	"strings"

	javascriptmeta "github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson/metadata"
	"github.com/google/osv-scalibr/purl"
)

// MakePackageURL returns a package URL for NPM PURLs. Technically they spec requires that package names be lowercase,
// but that'd make us not be able to disambiguate between some packages in the wild that still use uppercase.
// See https://github.com/package-url/purl-spec/issues/136
func MakePackageURL(name string, version string, metadata any) *purl.PackageURL {
	q := make(map[string]string)
	if m, ok := metadata.(*javascriptmeta.JavascriptPackageJSONMetadata); ok {
		if m.Source != javascriptmeta.Unknown {
			q["source"] = m.Source.ToProto().String()
		}
	}
	var qualifiers purl.Qualifiers
	if len(q) > 0 {
		qualifiers = purl.QualifiersFromMap(q)
	}
	namespace := ""
	if scope, packageName, ok := splitScopedPackageName(name); ok {
		namespace = scope
		name = packageName
	}
	return &purl.PackageURL{
		Type:       purl.TypeNPM,
		Namespace:  namespace,
		Name:       name,
		Version:    version,
		Qualifiers: qualifiers,
	}
}

func splitScopedPackageName(name string) (string, string, bool) {
	if !strings.HasPrefix(name, "@") {
		return "", "", false
	}
	parts := strings.Split(name, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}
