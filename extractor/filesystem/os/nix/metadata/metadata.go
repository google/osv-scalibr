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

// Package metadata defines a metadata struct for nix packages.
package metadata

import (
	"github.com/google/osv-scalibr/log"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// Metadata holds parsing information for a nix package.
type Metadata struct {
	PackageName       string
	PackageVersion    string
	PackageHash       string
	PackageOutput     string
	OSID              string
	OSVersionCodename string
	OSVersionID       string
}

// ToDistro extracts the OS distro from the metadata.
func (m *Metadata) ToDistro() string {
	if m.OSVersionCodename != "" {
		return m.OSVersionCodename
	}

	if m.OSVersionID != "" {
		return m.OSVersionID
	}

	log.Errorf("VERSION_CODENAME and VERSION_ID not set in os-release")

	return ""
}

// SetProto sets the NixPackageMetadata field in the Package proto.
func (m *Metadata) SetProto(p *pb.Package) {
	if m == nil {
		return
	}
	if p == nil {
		return
	}

	p.Metadata = &pb.Package_NixMetadata{
		NixMetadata: &pb.NixPackageMetadata{
			PackageName:       m.PackageName,
			PackageVersion:    m.PackageVersion,
			PackageHash:       m.PackageHash,
			PackageOutput:     m.PackageOutput,
			OsId:              m.OSID,
			OsVersionCodename: m.OSVersionCodename,
			OsVersionId:       m.OSVersionID,
		},
	}
}

// ToStruct converts the NixPackageMetadata proto to a Metadata struct.
func ToStruct(m *pb.NixPackageMetadata) *Metadata {
	if m == nil {
		return nil
	}

	return &Metadata{
		PackageName:       m.GetPackageName(),
		PackageVersion:    m.GetPackageVersion(),
		PackageHash:       m.GetPackageHash(),
		PackageOutput:     m.GetPackageOutput(),
		OSID:              m.GetOsId(),
		OSVersionCodename: m.GetOsVersionCodename(),
		OSVersionID:       m.GetOsVersionId(),
	}
}
