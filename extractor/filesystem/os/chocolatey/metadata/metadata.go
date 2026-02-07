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

// Package metadata defines a Metadata struct for Chocolatey packages.
package metadata

import (
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// Metadata holds parsing information for a Chocolatey package.
type Metadata struct {
	Name       string
	Version    string
	Authors    string
	LicenseURL string
	ProjectURL string
	Tags       string
}

// SetProto sets the ChocolateyMetadata field in the Package proto.
func (m *Metadata) SetProto(p *pb.Package) {
	if m == nil {
		return
	}
	if p == nil {
		return
	}

	p.Metadata = &pb.Package_ChocolateyMetadata{
		ChocolateyMetadata: &pb.ChocolateyPackageMetadata{
			Name:       m.Name,
			Version:    m.Version,
			Authors:    m.Authors,
			Licenseurl: m.LicenseURL,
			Projecturl: m.ProjectURL,
			Tags:       m.Tags,
		},
	}
}

// ToStruct converts the ChocolateyPackageMetadata proto to a Metadata struct.
func ToStruct(m *pb.ChocolateyPackageMetadata) *Metadata {
	if m == nil {
		return nil
	}

	return &Metadata{
		Name:       m.GetName(),
		Version:    m.GetVersion(),
		Authors:    m.GetAuthors(),
		LicenseURL: m.GetLicenseurl(),
		ProjectURL: m.GetProjecturl(),
		Tags:       m.GetTags(),
	}
}
