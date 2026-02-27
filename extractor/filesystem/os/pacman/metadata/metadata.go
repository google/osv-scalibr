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

// Package metadata defines a metadata struct for arch packages.
package metadata

import (
	"github.com/google/osv-scalibr/log"

	"github.com/google/osv-scalibr/binary/proto/metadataproto"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func init() {
	metadataproto.Register(ToStruct, ToProto)
}

// IsMetadata marks the struct as a metadata type.
func (m *Metadata) IsMetadata() {}

// Metadata holds parsing information for an arch package.
type Metadata struct {
	PackageName         string
	PackageVersion      string
	OSID                string
	OSVersionID         string
	PackageDependencies string
}

// ToNamespace extracts the PURL namespace from the metadata.
func (m *Metadata) ToNamespace() string {
	if m.OSID != "" {
		return m.OSID
	}
	log.Errorf("os-id not set, fallback to 'linux'")
	return "linux"
}

// ToDistro extracts the OS distro from the metadata.
func (m *Metadata) ToDistro() string {
	// fallback: e.g. 22.04
	if m.OSVersionID != "" {
		return m.OSVersionID
	}
	log.Errorf("VERSION_ID not set in os-release")
	return ""
}

// ToProto converts the Metadata struct to a PACMANPackageMetadata proto.
func ToProto(m *Metadata) *pb.PACMANPackageMetadata {
	return &pb.PACMANPackageMetadata{
		PackageName:         m.PackageName,
		PackageVersion:      m.PackageVersion,
		OsId:                m.OSID,
		OsVersionId:         m.OSVersionID,
		PackageDependencies: m.PackageDependencies,
	}
}

// ToStruct converts the PACMANPackageMetadata proto to a Metadata struct.
func ToStruct(m *pb.PACMANPackageMetadata) *Metadata {
	return &Metadata{
		PackageName:         m.GetPackageName(),
		PackageVersion:      m.GetPackageVersion(),
		OSID:                m.GetOsId(),
		OSVersionID:         m.GetOsVersionId(),
		PackageDependencies: m.GetPackageDependencies(),
	}
}
