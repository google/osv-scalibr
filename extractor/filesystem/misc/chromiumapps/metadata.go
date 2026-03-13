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

package chromiumapps

import (
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// SetProto sets the ChromiumAppsMetadata field on the Package proto.
func (m *Metadata) SetProto(p *pb.Package) {
	if m == nil || p == nil {
		return
	}
	p.Metadata = &pb.Package_ChromiumAppsMetadata{
		ChromiumAppsMetadata: &pb.ChromiumAppsMetadata{
			ChromiumVersion: m.ChromiumVersion,
			ElectronVersion: m.ElectronVersion,
			VersionSource:   m.VersionSource,
		},
	}
}

// ToStruct converts a ChromiumAppsMetadata proto to a Metadata struct.
func ToStruct(m *pb.ChromiumAppsMetadata) *Metadata {
	if m == nil {
		return nil
	}
	return &Metadata{
		ChromiumVersion: m.GetChromiumVersion(),
		ElectronVersion: m.GetElectronVersion(),
		VersionSource:   m.GetVersionSource(),
	}
}
