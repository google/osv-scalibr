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

// Package metadata defines a Go-specific metadata struct.
package metadata

import (
	metadataproto "github.com/google/osv-scalibr/binary/proto/metadata"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func init() {
	metadataproto.Register(ToStruct, ToProto)
}

// Metadata holds Go-specific package metadata.
type Metadata struct {
	// LocalReplacePath is a local filesystem path from a go.mod replace directive.
	// Remote replacements are applied directly to the package name and version.
	LocalReplacePath string
}

// IsProtoable marks the struct as a metadata type.
func (m *Metadata) IsProtoable() {}

// ToProto converts the Metadata struct to a GoMetadata proto.
func ToProto(m *Metadata) *pb.GoMetadata {
	return &pb.GoMetadata{
		LocalReplacePath: m.LocalReplacePath,
	}
}

// ToStruct converts the GoMetadata proto to a Metadata struct.
func ToStruct(m *pb.GoMetadata) *Metadata {
	return &Metadata{
		LocalReplacePath: m.GetLocalReplacePath(),
	}
}
