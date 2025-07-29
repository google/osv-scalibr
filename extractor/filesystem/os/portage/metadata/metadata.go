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

// Package metadata defines a metadata struct for portage packages.
package metadata

import (
	"github.com/google/osv-scalibr/log"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// Metadata holds parsing information for a portage package.
type Metadata struct {
	PackageName    string
	PackageVersion string
	OSID           string
	OSVersionID    string
}

// ToNamespace extracts the PURL namespace from the metadata.
func (m *Metadata) ToNamespace() string {
	if m.OSID != "" {
		return m.OSID
	}
	log.Errorf("os-release[ID] not set, fallback to 'linux'")
	return "linux"
}

// ToDistro extracts the OS distro from the metadata.
func (m *Metadata) ToDistro() string {
	if m.OSVersionID != "" {
		return m.OSVersionID
	}
	log.Errorf("VERSION_ID not set in os-release")
	return ""
}

// SetProto sets the PortagePackageMetadata field in the Package proto.
func (m *Metadata) SetProto(p *pb.Package) {
	if m == nil {
		return
	}
	if p == nil {
		return
	}

	p.Metadata = &pb.Package_PortageMetadata{
		PortageMetadata: &pb.PortagePackageMetadata{
			PackageName:    m.PackageName,
			PackageVersion: m.PackageVersion,
			OsId:           m.OSID,
			OsVersionId:    m.OSVersionID,
		},
	}
}

// ToStruct converts the PortagePackageMetadata proto to a Metadata struct.
func ToStruct(m *pb.PortagePackageMetadata) *Metadata {
	if m == nil {
		return nil
	}

	return &Metadata{
		PackageName:    m.GetPackageName(),
		PackageVersion: m.GetPackageVersion(),
		OSID:           m.GetOsId(),
		OSVersionID:    m.GetOsVersionId(),
	}
}
