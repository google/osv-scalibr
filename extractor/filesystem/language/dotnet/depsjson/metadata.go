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

package depsjson

import (
	"github.com/google/osv-scalibr/binary/proto/metadata"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func init() {
	metadata.Register(ToStruct, ToProto)
}

// Metadata holds parsing information for a deps.json package.
type Metadata struct {
	PackageName    string // The name of the package.
	PackageVersion string // The version of the package.
	// Type indicates the type of the package. Examples include:
	// - "package": Represents an external dependency, such as a NuGet package.
	// - "project": Represents an internal dependency, such as the main application
	Type string
}

// ToProto converts the Metadata struct to a DEPSJSONMetadata proto.
func ToProto(m *Metadata) *pb.DEPSJSONMetadata {
	return &pb.DEPSJSONMetadata{
		PackageName:    m.PackageName,
		PackageVersion: m.PackageVersion,
		Type:           m.Type,
	}
}

// IsProtoable marks the struct as a metadata type.
func (m *Metadata) IsProtoable() {}

// ToStruct converts the DEPSJSONMetadata proto to a Metadata struct.
func ToStruct(m *pb.DEPSJSONMetadata) *Metadata {
	return &Metadata{
		PackageName:    m.GetPackageName(),
		PackageVersion: m.GetPackageVersion(),
		Type:           m.GetType(),
	}
}
