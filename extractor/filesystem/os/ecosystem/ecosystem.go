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

// Package ecosystem converts OS package details into PackageURLs.
package ecosystem

import (
	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	modulemeta "github.com/google/osv-scalibr/extractor/filesystem/os/kernel/module/metadata"
	vmlinuzmeta "github.com/google/osv-scalibr/extractor/filesystem/os/kernel/vmlinuz/metadata"
	pacmanmeta "github.com/google/osv-scalibr/extractor/filesystem/os/pacman/metadata"
	portagemeta "github.com/google/osv-scalibr/extractor/filesystem/os/portage/metadata"
	rpmmeta "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	snapmeta "github.com/google/osv-scalibr/extractor/filesystem/os/snap/metadata"
	"github.com/google/osv-scalibr/log"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// MakeEcosystem computes the OSV Ecosystem value from an OS package's metadata.
func MakeEcosystem(metadata any) string {
	namespace := ""
	osVersionID := ""
	switch m := metadata.(type) {
	case *apkmeta.Metadata:
		version := m.ToDistro()
		if version == "" {
			return "Alpine"
		}
		return "Alpine:" + m.TrimDistroVersion(version)

	case *dpkgmeta.Metadata:
		namespace = m.ToNamespace()
		osVersionID = m.OSVersionID

	case *rpmmeta.Metadata:
		if m.OSID == "rhel" {
			return "Red Hat"
		} else if m.OSID == "rocky" {
			return "Rocky Linux"
		}

	case *snapmeta.Metadata:
		if m.OSID == "ubuntu" {
			return "Ubuntu"
		}
		log.Errorf("os-release[ID] not set, fallback to '' ecosystem")
		return ""

	case *pacmanmeta.Metadata:
		namespace = m.ToNamespace()
		osVersionID = m.OSVersionID

	case *portagemeta.Metadata:
		namespace = m.ToNamespace()
		osVersionID = m.OSVersionID

	case *vmlinuzmeta.Metadata:
		namespace = m.ToNamespace()
		osVersionID = m.OSVersionID

	case *modulemeta.Metadata:
		namespace = m.ToNamespace()
		osVersionID = m.OSVersionID

	default:
		return ""
	}

	osID := cases.Title(language.English).String(namespace)
	if osVersionID == "" {
		return osID
	}
	return osID + ":" + osVersionID
}
