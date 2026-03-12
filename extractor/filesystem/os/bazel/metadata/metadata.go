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

// Package metadata defines metadata structs for Bazel extractors.
package metadata

import (
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// MavenMetadata holds parsing information for a Bazel Maven dependency.
type MavenMetadata struct {
	Name       string // Full Name of the dependency
	GroupID    string // Maven group ID
	ArtifactID string // Maven artifact ID
	Version    string // Maven version
	RuleName   string // Bazel rule name
}

// SetProto sets the BazelMavenMetadata field in the Package proto.
func (m *MavenMetadata) SetProto(p *pb.Package) {
	if m == nil {
		return
	}
	if p == nil {
		return
	}

	p.Metadata = &pb.Package_BazelMavenMetadata{
		BazelMavenMetadata: &pb.BazelMavenMetadata{
			Name:       m.Name,
			GroupId:    m.GroupID,
			ArtifactId: m.ArtifactID,
			Version:    m.Version,
			RuleName:   m.RuleName,
		},
	}
}

// MavenToStruct converts the BazelMavenMetadata proto to a MavenMetadata struct.
func MavenToStruct(m *pb.BazelMavenMetadata) *MavenMetadata {
	if m == nil {
		return nil
	}

	return &MavenMetadata{
		Name:       m.GetName(),
		GroupID:    m.GetGroupId(),
		ArtifactID: m.GetArtifactId(),
		Version:    m.GetVersion(),
		RuleName:   m.GetRuleName(),
	}
}

// GoMetadata holds parsing information for a Bazel Go dependency.
type GoMetadata struct {
	RuleName string // Bazel rule name (e.g., "go_library", "go_binary", "go_test")
}

// SetProto sets the BazelGoMetadata field in the Package proto.
func (m *GoMetadata) SetProto(p *pb.Package) {
	if m == nil {
		return
	}
	if p == nil {
		return
	}

	p.Metadata = &pb.Package_BazelGoMetadata{
		BazelGoMetadata: &pb.BazelGoMetadata{
			RuleName: m.RuleName,
		},
	}
}

// GoToStruct converts the BazelGoMetadata proto to a GoMetadata struct.
func GoToStruct(m *pb.BazelGoMetadata) *GoMetadata {
	if m == nil {
		return nil
	}

	return &GoMetadata{
		RuleName: m.GetRuleName(),
	}
}
