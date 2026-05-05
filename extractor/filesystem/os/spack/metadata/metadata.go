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

// Package metadata defines a Metadata struct for spack packages.
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

// Metadata holds parsing information for a spack package.
type Metadata struct {
	Hash         string
	Platform     string
	PlatformOS   string
	Architecture string
}

// ToProto converts the Metadata struct to a SpackPackageMetadata proto.
func ToProto(m *Metadata) *pb.SpackPackageMetadata {
	return &pb.SpackPackageMetadata{
		Hash:                 m.Hash,
		Platform:             m.Platform,
		PlatformOs:           m.PlatformOS,
		PlatformArchitecture: m.Architecture,
	}
}

// ToStruct converts the SpackPackageMetadata proto to a Metadata struct.
func ToStruct(m *pb.SpackPackageMetadata) *Metadata {
	return &Metadata{
		Hash:         m.GetHash(),
		Platform:     m.GetPlatform(),
		PlatformOS:   m.GetPlatformOs(),
		Architecture: m.GetPlatformArchitecture(),
	}
}
