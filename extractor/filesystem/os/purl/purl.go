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

// Package purl converts OS package details into PackageURLs.
package purl

import (
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	"github.com/google/osv-scalibr/purl"
)

// MakePackageURL returns a package URL that follows the specific OS's spec
// and includes OS version info.
func MakePackageURL(_name string, version string, purlType string, metadata any) *purl.PackageURL {
	q := map[string]string{}
	var name string
	var namespace string
	switch m := metadata.(type) {
	case *dpkgmeta.Metadata:
		name = m.PackageName
		namespace = m.ToNamespace()

		distro := m.ToDistro()
		if distro != "" {
			q[purl.Distro] = distro
		}
		if m.SourceName != "" {
			q[purl.Source] = m.SourceName
		}
		if m.SourceVersion != "" {
			q[purl.SourceVersion] = m.SourceVersion
		}
		if m.Architecture != "" {
			q[purl.Arch] = m.Architecture
		}
	default:
		return nil
	}

	return &purl.PackageURL{
		Type:       purlType,
		Name:       name,
		Namespace:  namespace,
		Version:    version,
		Qualifiers: purl.QualifiersFromMap(q),
	}
}
