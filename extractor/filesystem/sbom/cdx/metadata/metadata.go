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

// Package metadata defines a Metadata struct for CDX packages.
package metadata

import (
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/purl/purlproto"

	"github.com/google/osv-scalibr/binary/proto/metadataproto"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func init() {
	metadataproto.Register(ToStruct, ToProto)
}

// Metadata holds parsing information for packages extracted from CDX files.
type Metadata struct {
	PURL         *purl.PackageURL
	CPEs         []string
	CDXLocations []string
}

// ToProto converts the CDX metadata struct to the CDXPackageMetadata proto.
func ToProto(m *Metadata) *pb.CDXPackageMetadata {
	return &pb.CDXPackageMetadata{
		Purl: purlproto.ToProto(m.PURL),
		Cpes: m.CPEs,
	}
}

// IsMetadata marks the struct as a metadata type.
func (m *Metadata) IsMetadata() {}

// ToStruct converts the SPDX metadata proto to the Metadata struct.
func ToStruct(m *pb.CDXPackageMetadata) *Metadata {
	return &Metadata{
		PURL: purlproto.FromProto(m.GetPurl()),
		CPEs: m.GetCpes(),
	}
}
