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

// Package fsmetadata provides a SCALIBR metadata type that wraps a scalibrfs.FS.
package fsmetadata

import (
	"github.com/google/osv-scalibr/binary/proto/metadataproto"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/google/osv-scalibr/fs"
)

func init() {
	metadataproto.Register(ToStruct, ToProto)
}

// Metadata wraps a scalibrfs.FS.
//
//nolint:plugger
type Metadata struct {
	FS        fs.FS
	Converted bool
}

// IsMetadata marks the struct as a metadata type.
func (m *Metadata) IsMetadata() {}

// ToProto returns a placeholder proto.
func ToProto(m *Metadata) *pb.FSMetadata {
	return &pb.FSMetadata{HasFs: m.FS != nil}
}

// ToStruct returns the struct with Converted=true and FS=nil.
func ToStruct(m *pb.FSMetadata) *Metadata {
	return &Metadata{
		Converted: true,
		FS:        nil,
	}
}
