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

package wheelegg

import (
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// PythonPackageMetadata holds parsing information from a python egg or wheel package.
type PythonPackageMetadata struct {
	Author      string `json:"author"`
	AuthorEmail string `json:"authorEmail"`
}

// ToProto converts the Metadata struct to a PythonPackageMetadata proto.
func (m *PythonPackageMetadata) ToProto() *pb.PythonPackageMetadata {
	return &pb.PythonPackageMetadata{
		Author:      m.Author,
		AuthorEmail: m.AuthorEmail,
	}
}

// SetProto sets the PythonMetadata field in the Package proto.
func (m *PythonPackageMetadata) SetProto(p *pb.Package) {
	p.Metadata = &pb.Package_PythonMetadata{
		PythonMetadata: m.ToProto(),
	}
}

// ToStruct converts the PythonPackageMetadata proto to a Metadata struct.
func ToStruct(m *pb.PythonPackageMetadata) *PythonPackageMetadata {
	return &PythonPackageMetadata{
		Author:      m.GetAuthor(),
		AuthorEmail: m.GetAuthorEmail(),
	}
}
