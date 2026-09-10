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

package pyprojecttoml

import (
	"cmp"
	"slices"

	"github.com/google/osv-scalibr/binary/proto/metadata"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func init() {
	metadata.Register(ToStruct, ToProto)
}

// Metadata contains information about the Python package declared by a PEP-621 pyproject.toml.
type Metadata struct {
	HasDynamicDependencies bool                `json:"has-dynamic-dependencies"`
	Dependencies           []string            `json:"dependencies"`
	OptionalDependencies   map[string][]string `json:"optional-dependencies"`
}

// ToProto converts the Metadata struct to a PythonPyprojectTomlMetadata proto.
func ToProto(m *Metadata) *pb.PyprojectMetadata {
	optional := make([]*pb.PyprojectMetadata_DependencyGroup, 0, len(m.OptionalDependencies))
	for name, group := range m.OptionalDependencies {
		optional = append(optional, &pb.PyprojectMetadata_DependencyGroup{
			Name:         name,
			Dependencies: group,
		})
	}
	slices.SortFunc(optional, func(a, b *pb.PyprojectMetadata_DependencyGroup) int {
		return cmp.Compare(a.GetName(), b.GetName())
	})
	return &pb.PyprojectMetadata{
		HasDynamicDependencies: m.HasDynamicDependencies,
		Dependencies:           &pb.PyprojectMetadata_DependencyGroup{Dependencies: m.Dependencies},
		OptionalDependencies:   optional,
	}
}

// IsProtoable marks the struct as a metadata type.
func (m *Metadata) IsProtoable() {}

// ToStruct converts the PythonPyprojectTomlMetadata proto to a Metadata struct.
func ToStruct(m *pb.PyprojectMetadata) *Metadata {
	optional := make(map[string][]string, len(m.GetOptionalDependencies()))
	for _, group := range m.GetOptionalDependencies() {
		optional[group.GetName()] = group.GetDependencies()
	}
	return &Metadata{
		HasDynamicDependencies: m.GetHasDynamicDependencies(),
		Dependencies:           m.GetDependencies().GetDependencies(),
		OptionalDependencies:   optional,
	}
}
