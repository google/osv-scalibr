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

// Package metadata defines a metadata struct for NVM Node.js versions.
package metadata

import (
	"github.com/google/osv-scalibr/binary/proto/metadataproto"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func init() {
	metadataproto.Register(ToStruct, ToProto)
}

// Metadata holds parsing information for an NVM Node.js version.
type Metadata struct {
	NodeJsVersion string
}

// ToProto converts the Metadata struct to a NvmMetadata proto.
func ToProto(m *Metadata) *pb.NvmMetadata {
	return &pb.NvmMetadata{
		NodejsVersion: m.NodeJsVersion,
	}
}

// IsMetadata marks the struct as a metadata type.
func (m *Metadata) IsMetadata() {}

// ToStruct converts the NvmMetadata proto to a Metadata struct.
func ToStruct(m *pb.NvmMetadata) *Metadata {

	return &Metadata{
		NodeJsVersion: m.GetNodejsVersion(),
	}
}
