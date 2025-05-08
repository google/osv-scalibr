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

// Package purl converts a package to a Maven type PackageURL.
package purl

import (
	"strings"

	archivemeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/purl"
)

// MakePackageURL returns a package URL from a version string and a Maven specific metadata struct
// according to the Maven PURL spec:
// - Group ID is lowercased and stored as the namespace
// - Artifact ID is lowercased and stored as the name
func MakePackageURL(version string, metadata any) *purl.PackageURL {
	switch m := metadata.(type) {
	case *archivemeta.Metadata:
		return &purl.PackageURL{
			Type:      purl.TypeMaven,
			Namespace: strings.ToLower(m.GroupID),
			Name:      strings.ToLower(m.ArtifactID),
			Version:   version,
		}
	case *javalockfile.Metadata:
		q := map[string]string{}
		if m.Classifier != "" {
			q[purl.Classifier] = m.Classifier
		}
		if m.Type != "" {
			q[purl.Type] = m.Type
		}
		var qualifiers purl.Qualifiers
		if len(q) > 0 {
			qualifiers = purl.QualifiersFromMap(q)
		}
		return &purl.PackageURL{
			Type:       purl.TypeMaven,
			Namespace:  strings.ToLower(m.GroupID),
			Name:       strings.ToLower(m.ArtifactID),
			Version:    version,
			Qualifiers: qualifiers,
		}
	default:
		return nil
	}
}
