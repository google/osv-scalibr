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

package wheelegg

import (
	"github.com/google/osv-scalibr/binary/proto/metadataproto"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func init() {
	metadataproto.Register(ToStruct, ToProto)
}

// PythonPackageMetadata holds parsing information from a python egg or wheel package.
type PythonPackageMetadata struct {
	Author      string `json:"author"`
	AuthorEmail string `json:"authorEmail"`
}

// ToProto converts the PythonPackageMetadata struct to a PythonPackageMetadata proto.
func ToProto(m *PythonPackageMetadata) *pb.PythonPackageMetadata {
	return &pb.PythonPackageMetadata{
		Author:      m.Author,
		AuthorEmail: m.AuthorEmail,
	}
}

// IsMetadata marks the struct as a metadata type.
func (m *PythonPackageMetadata) IsMetadata() {}

// ToStruct converts the PythonPackageMetadata proto to a Metadata struct.
func ToStruct(m *pb.PythonPackageMetadata) *PythonPackageMetadata {

	return &PythonPackageMetadata{
		Author:      m.GetAuthor(),
		AuthorEmail: m.GetAuthorEmail(),
	}
}
