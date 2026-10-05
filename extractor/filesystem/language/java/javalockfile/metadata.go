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

// Package javalockfile provides shared structures for Java extractors.
package javalockfile

import (
	"deps.dev/util/maven"
	"github.com/google/osv-scalibr/binary/proto/metadata"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func init() {
	metadata.Register(ToStruct, ToProto)
}

// Metadata holds parsing information for a Java package.
type Metadata struct {
	ArtifactID   string
	GroupID      string
	Type         string
	Classifier   string
	DepGroupVals []string
	IsTransitive bool // Only set in transitive dependency pomxml enricher
}

// DepGroups returns the dependency groups for the package.
func (m Metadata) DepGroups() []string {
	return m.DepGroupVals
}

// ToProto converts the Metadata struct to a JavaLockfileMetadata proto.
func ToProto(m *Metadata) *pb.JavaLockfileMetadata {
	return &pb.JavaLockfileMetadata{
		ArtifactId:   m.ArtifactID,
		GroupId:      m.GroupID,
		DepGroupVals: m.DepGroupVals,
		IsTransitive: m.IsTransitive,
	}
}

// IsProtoable marks the struct as a metadata type.
func (m *Metadata) IsProtoable() {}

// ToStruct converts the JavaLockfileMetadata proto to a Metadata struct.
func ToStruct(m *pb.JavaLockfileMetadata) *Metadata {
	return &Metadata{
		ArtifactID:   m.GetArtifactId(),
		GroupID:      m.GetGroupId(),
		DepGroupVals: m.GetDepGroupVals(),
		IsTransitive: m.GetIsTransitive(),
	}
}

// DependenciesToProto converts a slice of maven.Dependency to a slice of JavaLockfileDependency protos.
func DependenciesToProto(dependencies []maven.Dependency) []*pb.JavaLockfileDependency {
	var protos []*pb.JavaLockfileDependency
	for _, d := range dependencies {
		protos = append(protos, &pb.JavaLockfileDependency{
			GroupId:            string(d.GroupID),
			ArtifactId:         string(d.ArtifactID),
			VersionRequirement: string(d.Version),
			Scope:              string(d.Scope),
			IsOptional:         d.Optional.Boolean(),
		})
	}
	return protos
}

// DependenciesToStruct converts a slice of JavaLockfileDependency protos to a slice of maven.Dependency.
func DependenciesToStruct(protos []*pb.JavaLockfileDependency) []maven.Dependency {
	var dependencies []maven.Dependency
	for _, p := range protos {
		var optional maven.FalsyBool = "false"
		if p.GetIsOptional() {
			optional = "true"
		}
		dependencies = append(dependencies, maven.Dependency{
			GroupID:    maven.String(p.GetGroupId()),
			ArtifactID: maven.String(p.GetArtifactId()),
			Version:    maven.String(p.GetVersionRequirement()),
			Scope:      maven.String(p.GetScope()),
			Optional:   optional,
		})
	}
	return dependencies
}

// ParentToProto converts a maven.ProjectKey (representing a parent project) to a JavaLockfileParent proto.
//
// Explicitly allows nil as input, to simplify working with projects with no parent.
func ParentToProto(key *maven.ProjectKey) *pb.JavaLockfileParent {
	if key == nil {
		return nil
	}
	return &pb.JavaLockfileParent{
		GroupId:    string(key.GroupID),
		ArtifactId: string(key.ArtifactID),
		Version:    string(key.Version),
	}
}

// ParentToStruct converts a JavaLockfileParent proto to a maven.ProjectKey.
//
// Same as [ParentToProto], explicitly allows nil as input.
func ParentToStruct(parent *pb.JavaLockfileParent) *maven.ProjectKey {
	if parent == nil {
		return nil
	}
	return &maven.ProjectKey{
		GroupID:    maven.String(parent.GetGroupId()),
		ArtifactID: maven.String(parent.GetArtifactId()),
		Version:    maven.String(parent.GetVersion()),
	}
}
