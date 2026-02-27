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

// Package metadata provides metadata structures to annotate Windows packages.
package metadata

import (
	"github.com/google/osv-scalibr/binary/proto/metadataproto"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func init() {
	metadataproto.Register(ToStruct, ToProto)
}

// OSVersion provides metadata about the OS version.
type OSVersion struct {
	// Product name of the OS, e.g. "windows_server_2019".
	Product string
	// FullVersion is the full version of the OS version: Major.Minor.Build.Revision.
	FullVersion string
}

// ToProto converts the OSVersion struct to a WindowsOSVersion proto.
func ToProto(m *OSVersion) *pb.WindowsOSVersion {
	return &pb.WindowsOSVersion{
		Product:     m.Product,
		FullVersion: m.FullVersion,
	}
}

// IsMetadata marks the struct as a metadata type.
func (m *OSVersion) IsMetadata() {}

// ToStruct converts the WindowsOSVersion proto to a Metadata struct.
func ToStruct(m *pb.WindowsOSVersion) *OSVersion {
	return &OSVersion{
		Product:     m.GetProduct(),
		FullVersion: m.GetFullVersion(),
	}
}
