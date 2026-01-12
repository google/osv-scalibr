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

// Package metadata provides metadata structures to annotate Windows packages.
package metadata

import (
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// OSVersion provides metadata about the OS version.
type OSVersion struct {
	// Product name of the OS, e.g. "windows_server_2019".
	Product string
	// FullVersion is the full version of the OS version: Major.Minor.Build.Revision.
	FullVersion string
}

// SetProto sets the WindowsOSVersionMetadata field in the Package proto.
func (m *OSVersion) SetProto(p *pb.Package) {
	if m == nil {
		return
	}
	if p == nil {
		return
	}

	p.Metadata = &pb.Package_WindowsOsVersionMetadata{
		WindowsOsVersionMetadata: &pb.WindowsOSVersion{
			Product:     m.Product,
			FullVersion: m.FullVersion,
		},
	}
}

// ToStruct converts the WindowsOSVersion proto to a Metadata struct.
func ToStruct(m *pb.WindowsOSVersion) *OSVersion {
	if m == nil {
		return nil
	}

	return &OSVersion{
		Product:     m.GetProduct(),
		FullVersion: m.GetFullVersion(),
	}
}
