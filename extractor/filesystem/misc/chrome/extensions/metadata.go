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

package extensions

import (
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// Metadata contains metadata for Chrome extensions.
type Metadata struct {
	Name                 string
	Description          string
	AuthorEmail          string
	HostPermissions      []string
	ManifestVersion      int
	MinimumChromeVersion string
	Permissions          []string
	UpdateURL            string
}

// SetProto sets the ChromeExtensionsMetadata field in the Package proto.
func (m *Metadata) SetProto(p *pb.Package) {
	if m == nil {
		return
	}
	if p == nil {
		return
	}

	p.Metadata = &pb.Package_ChromeExtensionsMetadata{
		ChromeExtensionsMetadata: &pb.ChromeExtensionsMetadata{
			Name:                 m.Name,
			Description:          m.Description,
			AuthorEmail:          m.AuthorEmail,
			HostPermissions:      m.HostPermissions,
			ManifestVersion:      int32(m.ManifestVersion),
			MinimumChromeVersion: m.MinimumChromeVersion,
			Permissions:          m.Permissions,
			UpdateUrl:            m.UpdateURL,
		},
	}
}

// ToStruct converts the ChromeExtensionsMetadata proto to a Metadata struct.
func ToStruct(m *pb.ChromeExtensionsMetadata) *Metadata {
	if m == nil {
		return nil
	}

	return &Metadata{
		Name:                 m.GetName(),
		Description:          m.GetDescription(),
		AuthorEmail:          m.GetAuthorEmail(),
		HostPermissions:      m.GetHostPermissions(),
		ManifestVersion:      int(m.GetManifestVersion()),
		MinimumChromeVersion: m.GetMinimumChromeVersion(),
		Permissions:          m.GetPermissions(),
		UpdateURL:            m.GetUpdateUrl(),
	}
}
