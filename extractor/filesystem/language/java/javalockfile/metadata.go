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

// Package javalockfile provides shared structures for Java extractors.
package javalockfile

import (
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/google/osv-scalibr/clients/datasource"
)

// Metadata holds parsing information for a Java package.
type Metadata struct {
	ArtifactID   string
	GroupID      string
	Type         string
	Classifier   string
	DepGroupVals []string
	IsTransitive bool // Only set in pomxmlnet extractor
	Registries   []datasource.MavenRegistry
}

// DepGroups returns the dependency groups for the package.
func (m Metadata) DepGroups() []string {
	return m.DepGroupVals
}

// SetProto sets the JavaLockfileMetadata field in the Package proto.
func (m *Metadata) SetProto(p *pb.Package) {
	if m == nil {
		return
	}
	if p == nil {
		return
	}

	p.Metadata = &pb.Package_JavaLockfileMetadata{
		JavaLockfileMetadata: &pb.JavaLockfileMetadata{
			ArtifactId:   m.ArtifactID,
			GroupId:      m.GroupID,
			DepGroupVals: m.DepGroupVals,
			IsTransitive: m.IsTransitive,
		},
	}
}

// ToStruct converts the JavaLockfileMetadata proto to a Metadata struct.
func ToStruct(m *pb.JavaLockfileMetadata) *Metadata {
	if m == nil {
		return nil
	}

	return &Metadata{
		ArtifactID:   m.GetArtifactId(),
		GroupID:      m.GetGroupId(),
		DepGroupVals: m.GetDepGroupVals(),
		IsTransitive: m.GetIsTransitive(),
	}
}
