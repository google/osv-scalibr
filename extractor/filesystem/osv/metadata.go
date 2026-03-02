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

// Package osv defines OSV-specific fields for parsed source packages.
package osv

import (
	"github.com/google/osv-scalibr/binary/proto/metadataproto"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func init() {
	metadataproto.Register(ToStruct, ToProto)
	metadataproto.Register(DepGroupToStruct, DepGroupToProto)
}

// Metadata holds parsing information for packages extracted by an OSV extractor wrapper.
type Metadata struct {
	PURLType  string
	Commit    string
	Ecosystem string
	CompareAs string
}

// ToProto converts the Metadata struct to an OSVPackageMetadata proto.
func ToProto(m *Metadata) *pb.OSVPackageMetadata {
	return &pb.OSVPackageMetadata{
		PurlType:  m.PURLType,
		Commit:    m.Commit,
		Ecosystem: m.Ecosystem,
		CompareAs: m.CompareAs,
	}
}

// IsMetadata marks the struct as a metadata type.
func (m *Metadata) IsMetadata() {}

// ToStruct converts the OSVPackageMetadata proto to a Metadata struct.
func ToStruct(m *pb.OSVPackageMetadata) *Metadata {
	return &Metadata{
		PURLType:  m.GetPurlType(),
		Commit:    m.GetCommit(),
		Ecosystem: m.GetEcosystem(),
		CompareAs: m.GetCompareAs(),
	}
}

// DepGroups provides access to the list of dependency groups a package item belongs to.
// Dependency groups are used by many language package managers as a way to organize
// dependencies (e.g. development dependencies will be in the "dev" group)
type DepGroups interface {
	DepGroups() []string
}

// DepGroupMetadata is a metadata struct that only supports DepGroups
type DepGroupMetadata struct {
	DepGroupVals []string
}

var _ DepGroups = DepGroupMetadata{}

// DepGroups return the dependency groups property in the metadata
func (dgm DepGroupMetadata) DepGroups() []string {
	return dgm.DepGroupVals
}

// DepGroupToProto converts the DepGroupMetadata struct to a DepGroupMetadata proto.
func DepGroupToProto(dgm *DepGroupMetadata) *pb.DepGroupMetadata {
	return &pb.DepGroupMetadata{
		DepGroupVals: dgm.DepGroupVals,
	}
}

// IsMetadata marks the struct as a metadata type.
func (dgm *DepGroupMetadata) IsMetadata() {}

// DepGroupToStruct converts the DepGroupMetadata proto to a DepGroupMetadata struct.
func DepGroupToStruct(m *pb.DepGroupMetadata) *DepGroupMetadata {
	return &DepGroupMetadata{
		DepGroupVals: m.GetDepGroupVals(),
	}
}
