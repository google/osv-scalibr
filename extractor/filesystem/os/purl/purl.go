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
	"strconv"
	"strings"

	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	cosmeta "github.com/google/osv-scalibr/extractor/filesystem/os/cos/metadata"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	flatpakmeta "github.com/google/osv-scalibr/extractor/filesystem/os/flatpak/metadata"
	nixmeta "github.com/google/osv-scalibr/extractor/filesystem/os/nix/metadata"
	pacmanmeta "github.com/google/osv-scalibr/extractor/filesystem/os/pacman/metadata"
	portagemeta "github.com/google/osv-scalibr/extractor/filesystem/os/portage/metadata"
	rpmmeta "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	snapmeta "github.com/google/osv-scalibr/extractor/filesystem/os/snap/metadata"
	"github.com/google/osv-scalibr/purl"
)

// MakePackageURL returns a package URL that follows the specific OS's spec
// and includes OS version info.
func MakePackageURL(name string, version string, purlType string, metadata any) *purl.PackageURL {
	q := map[string]string{}
	var namespace string
	switch m := metadata.(type) {
	case *apkmeta.Metadata:
		namespace = m.ToNamespace()
		name = strings.ToLower(name)
		if distro := m.ToDistro(); distro != "" {
			q[purl.Distro] = distro
		}
		if m.OriginName != "" {
			q[purl.Origin] = m.OriginName
		}
		if m.Architecture != "" {
			q[purl.Arch] = m.Architecture
		}

	case *cosmeta.Metadata:
		if distro := m.ToDistro(); distro != "" {
			q[purl.Distro] = distro
		}

	case *dpkgmeta.Metadata:
		namespace = m.ToNamespace()
		name = m.PackageName

		if distro := m.ToDistro(); distro != "" {
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

	case *flatpakmeta.Metadata:
		namespace = m.ToNamespace()
		if distro := m.ToDistro(); distro != "" {
			q[purl.Distro] = distro
		}

	case *rpmmeta.Metadata:
		namespace = m.ToNamespace()
		if m.Epoch > 0 {
			q[purl.Epoch] = strconv.Itoa(m.Epoch)
		}
		if distro := m.ToDistro(); distro != "" {
			q[purl.Distro] = distro
		}
		if m.SourceRPM != "" {
			q[purl.SourceRPM] = m.SourceRPM
		}
		if m.Architecture != "" {
			q[purl.Arch] = m.Architecture
		}

	case *snapmeta.Metadata:
		namespace = m.ToNamespace()
		if distro := m.ToDistro(); distro != "" {
			q[purl.Distro] = distro
		}

	case *pacmanmeta.Metadata:
		namespace = m.ToNamespace()
		name = m.PackageName
		if distro := m.ToDistro(); distro != "" {
			q[purl.Distro] = distro
		}
		if m.PackageDependencies != "" {
			q[purl.PackageDependencies] = m.PackageDependencies
		}

	case *portagemeta.Metadata:
		namespace = m.ToNamespace()
		name = m.PackageName
		version = m.PackageVersion
		if distro := m.ToDistro(); distro != "" {
			q[purl.Distro] = distro
		}

	case *nixmeta.Metadata:
		if distro := m.ToDistro(); distro != "" {
			q[purl.Distro] = distro
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
