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

// Package metadata defines a Metadata struct for SPDX packages.
package metadata

import (
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/purl/purlproto"

	"github.com/google/osv-scalibr/binary/proto/metadata"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func init() {
	metadata.Register(ToStruct, ToProto)
}

// ExternalReference represents an external reference in an SPDX package.
type ExternalReference struct {
	Category string
	RefType  string
	Locator  string
	Comment  string
}

// Metadata holds parsing information for packages extracted from SPDX files.
type Metadata struct {
	PURL               *purl.PackageURL
	CPEs               []string
	ExternalReferences []ExternalReference
	SPDXID             string
}

// ToProto converts the SPDX metadata struct to the SPDXPackageMetadata proto.
func ToProto(m *Metadata) *pb.SPDXPackageMetadata {
	var extRefs []*pb.SPDXExternalReference
	for _, ref := range m.ExternalReferences {
		extRefs = append(extRefs, &pb.SPDXExternalReference{
			Category: ref.Category,
			RefType:  ref.RefType,
			Locator:  ref.Locator,
			Comment:  ref.Comment,
		})
	}
	return &pb.SPDXPackageMetadata{
		Purl:               purlproto.ToProto(m.PURL),
		Cpes:               m.CPEs,
		ExternalReferences: extRefs,
		SpdxId:             m.SPDXID,
	}
}

// IsProtoable marks the struct as a metadata type.
func (m *Metadata) IsProtoable() {}

// ToStruct converts the SPDX metadata proto to the Metadata struct.
func ToStruct(m *pb.SPDXPackageMetadata) *Metadata {
	var extRefs []ExternalReference
	for _, ref := range m.GetExternalReferences() {
		extRefs = append(extRefs, ExternalReference{
			Category: ref.GetCategory(),
			RefType:  ref.GetRefType(),
			Locator:  ref.GetLocator(),
			Comment:  ref.GetComment(),
		})
	}
	return &Metadata{
		PURL:               purlproto.FromProto(m.GetPurl()),
		CPEs:               m.GetCpes(),
		ExternalReferences: extRefs,
		SPDXID:             m.GetSpdxId(),
	}
}
