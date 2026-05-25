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

// Package metadata defines a metadata struct for FreeBSD pkg packages.
package metadata

import (
	"github.com/google/osv-scalibr/binary/proto/metadata"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func init() {
	metadata.Register(ToStruct, ToProto)
}

// IsProtoable marks the struct as a metadata type.
func (m *Metadata) IsProtoable() {}

// Metadata holds parsing information for a FreeBSD pkg package.
type Metadata struct {
	PackageName    string
	PackageVersion string
	Origin         string
	Arch           string
	OSID           string
	OSVersionID    string
}

// ToDistro extracts the OS distro from the metadata.
func (m *Metadata) ToDistro() string {
	return m.OSVersionID
}

// ToProto converts the Metadata struct to a FreeBSDPackageMetadata proto.
func ToProto(m *Metadata) *pb.FreeBSDPackageMetadata {
	if m == nil {
		return nil
	}
	return &pb.FreeBSDPackageMetadata{
		PackageName:    m.PackageName,
		PackageVersion: m.PackageVersion,
		Origin:         m.Origin,
		Arch:           m.Arch,
		OsId:           m.OSID,
		OsVersionId:    m.OSVersionID,
	}
}

// ToStruct converts the FreeBSDPackageMetadata proto to a Metadata struct.
func ToStruct(m *pb.FreeBSDPackageMetadata) *Metadata {
	if m == nil {
		return nil
	}
	return &Metadata{
		PackageName:    m.GetPackageName(),
		PackageVersion: m.GetPackageVersion(),
		Origin:         m.GetOrigin(),
		Arch:           m.GetArch(),
		OSID:           m.GetOsId(),
		OSVersionID:    m.GetOsVersionId(),
	}
}
