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

// Package metadata defines a metadata struct for Node.js versions.
package metadata

import (
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// Metadata holds parsing information for a Node.js version.
type Metadata struct {
	NodeJsVersion string
}

// SetProto sets the NodeVersionMetadata field in the Package proto.
func (m *Metadata) SetProto(p *pb.Package) {
	if m == nil {
		return
	}
	if p == nil {
		return
	}

	p.Metadata = &pb.Package_NodeversionMetadata{
		NodeversionMetadata: &pb.NodeVersionMetadata{
			NodejsVersion: m.NodeJsVersion,
		},
	}
}

// ToStruct converts the NodeVersionMetadata proto to a Metadata struct.
func ToStruct(m *pb.NodeVersionMetadata) *Metadata {
	if m == nil {
		return nil
	}

	return &Metadata{
		NodeJsVersion: m.GetNodejsVersion(),
	}
}
