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
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// Metadata holds parsing information for packages extracted by an OSV extractor wrapper.
type Metadata struct {
	PURLType  string
	Commit    string
	Ecosystem string
	CompareAs string
}

// SetProto sets the OSVPackageMetadata field in the Package proto.
func (m *Metadata) SetProto(p *pb.Package) {
	if m == nil {
		return
	}
	if p == nil {
		return
	}

	p.Metadata = &pb.Package_OsvMetadata{
		OsvMetadata: &pb.OSVPackageMetadata{
			PurlType:  m.PURLType,
			Commit:    m.Commit,
			Ecosystem: m.Ecosystem,
			CompareAs: m.CompareAs,
		},
	}
}

// ToStruct converts the OSVPackageMetadata proto to a Metadata struct.
func ToStruct(m *pb.OSVPackageMetadata) *Metadata {
	if m == nil {
		return nil
	}

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

// SetProto sets the DepGroupMetadata field in the Package proto.
func (dgm DepGroupMetadata) SetProto(p *pb.Package) {
	if len(dgm.DepGroupVals) == 0 {
		return
	}
	p.Metadata = &pb.Package_DepGroupMetadata{
		DepGroupMetadata: &pb.DepGroupMetadata{
			DepGroupVals: dgm.DepGroupVals,
		},
	}
}

// DepGroupToStruct converts the DepGroupMetadata proto to a DepGroupMetadata struct.
func DepGroupToStruct(m *pb.DepGroupMetadata) *DepGroupMetadata {
	if m == nil {
		return nil
	}
	return &DepGroupMetadata{
		DepGroupVals: m.GetDepGroupVals(),
	}
}
