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

package depsjson

import (
	"github.com/google/osv-scalibr/internal/proto/packagemetadata"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// Metadata holds parsing information for a deps.json package.
type Metadata struct {
	PackageName    string // The name of the package.
	PackageVersion string // The version of the package.
	// Type indicates the type of the package. Examples include:
	// - "package": Represents an external dependency, such as a NuGet package.
	// - "project": Represents an internal dependency, such as the main application
	Type string
}

// Converter converts between struct and proto representations of deps.json metadata.
type Converter struct{}

// ToStruct converts a proto representation of deps.json metadata to a struct.
func (c Converter) ToStruct(p *pb.DEPSJSONMetadata) *Metadata {
	if p == nil {
		return nil
	}

	return &Metadata{
		PackageName:    p.GetPackageName(),
		PackageVersion: p.GetPackageVersion(),
		Type:           p.GetType(),
	}
}

// ToProto converts a struct representation of deps.json metadata to a proto.
func (c Converter) ToProto(m *Metadata) *pb.DEPSJSONMetadata {
	if m == nil {
		return nil
	}

	return &pb.DEPSJSONMetadata{
		PackageName:    m.PackageName,
		PackageVersion: m.PackageVersion,
		Type:           m.Type,
	}
}

// GetProtoMetadata returns the proto representation of deps.json metadata from the package proto.
func (c Converter) GetProtoMetadata(p *pb.Package_DepsjsonMetadata) *pb.DEPSJSONMetadata {
	return p.DepsjsonMetadata
}

func init() {
	packagemetadata.Register(Converter{}, func(p *pb.Package, m *pb.DEPSJSONMetadata) {
		p.Metadata = &pb.Package_DepsjsonMetadata{
			DepsjsonMetadata: m,
		}
	})
}
