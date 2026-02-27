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

// Package metadata defines a Metadata struct for Homebrew packages.
package metadata

import (
	"github.com/google/osv-scalibr/binary/proto/metadataproto"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func init() {
	metadataproto.Register(ToStruct, ToProto)
}

// IsMetadata marks the struct as a metadata type.
func (m *Metadata) IsMetadata() {}

// Metadata holds parsing information for a Homebrew package.
type Metadata struct {
	URL     string
	Head    string
	Mirrors []string
}

// ToProto converts the Metadata struct to a HomebrewPackageMetadata proto.
func ToProto(m *Metadata) *pb.HomebrewPackageMetadata {
	return &pb.HomebrewPackageMetadata{
		Url:     m.URL,
		Head:    m.Head,
		Mirrors: m.Mirrors,
	}
}

// ToStruct converts the HomebrewPackageMetadata proto to a Metadata struct.
func ToStruct(m *pb.HomebrewPackageMetadata) *Metadata {
	return &Metadata{
		URL:     m.GetUrl(),
		Head:    m.GetHead(),
		Mirrors: m.GetMirrors(),
	}
}
