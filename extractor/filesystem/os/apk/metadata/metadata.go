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

// Package metadata defines a Metadata struct for apk packages.
package metadata

import (
	"fmt"
	"strings"

	"github.com/google/osv-scalibr/log"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// Metadata holds parsing information for an apk package.
type Metadata struct {
	PackageName  string
	OriginName   string
	OSID         string
	OSVersionID  string
	Maintainer   string
	Architecture string
}

// ToNamespace extracts the PURL namespace from the metadata.
func (m *Metadata) ToNamespace() string {
	if m.OSID != "" {
		return m.OSID
	}
	log.Errorf("os-release[ID] not set, fallback to 'alpine'")
	return "alpine"
}

// ToDistro extracts the OS distro from the metadata.
func (m *Metadata) ToDistro() string {
	// e.g. 3.18.0
	if m.OSVersionID != "" {
		return m.OSVersionID
	}
	log.Errorf("VERSION_ID not set in os-release")
	return ""
}

// TrimDistroVersion trims minor versions from the distro string.
// The Alpine OS info might include minor versions such as 3.12.1 while advisories are
// only published against the minor and major versions, i.e. v3.12. Therefore we trim
// any minor versions before putting the value into the Ecosystem.
func (Metadata) TrimDistroVersion(distro string) string {
	parts := strings.Split(distro, ".")
	if len(parts) < 2 {
		return "v" + distro
	}
	return fmt.Sprintf("v%s.%s", parts[0], parts[1])
}

// SetProto sets the ApkMetadata field in the Package proto.
func (m *Metadata) SetProto(p *pb.Package) {
	if m == nil {
		return
	}
	if p == nil {
		return
	}

	p.Metadata = &pb.Package_ApkMetadata{
		ApkMetadata: &pb.APKPackageMetadata{
			PackageName:  m.PackageName,
			OriginName:   m.OriginName,
			OsId:         m.OSID,
			OsVersionId:  m.OSVersionID,
			Maintainer:   m.Maintainer,
			Architecture: m.Architecture,
		},
	}
}

// ToStruct converts the APKPackageMetadata proto to a Metadata struct.
func ToStruct(m *pb.APKPackageMetadata) *Metadata {
	if m == nil {
		return nil
	}

	return &Metadata{
		PackageName:  m.GetPackageName(),
		OriginName:   m.GetOriginName(),
		OSID:         m.GetOsId(),
		OSVersionID:  m.GetOsVersionId(),
		Maintainer:   m.GetMaintainer(),
		Architecture: m.GetArchitecture(),
	}
}
