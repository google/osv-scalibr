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

package pyprojecttoml_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pyprojecttoml"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestConversion(t *testing.T) {
	testCases := []struct {
		name  string
		input *pyprojecttoml.Metadata
		want  *pb.PyprojectMetadata
	}{
		{
			name:  "empty",
			input: &pyprojecttoml.Metadata{},
			want:  &pb.PyprojectMetadata{Dependencies: &pb.PyprojectMetadata_DependencyGroup{}},
		},
		{
			name: "all_fields",
			input: &pyprojecttoml.Metadata{
				HasDynamicDependencies: true,
				Dependencies:           []string{"requests", "flask"},
				OptionalDependencies: map[string][]string{
					"async": {"aiohttp", "fastapi"},
					"dev":   {"pytest", "black"},
				},
			},
			want: &pb.PyprojectMetadata{
				HasDynamicDependencies: true,
				Dependencies: &pb.PyprojectMetadata_DependencyGroup{
					Dependencies: []string{"requests", "flask"},
				},
				OptionalDependencies: []*pb.PyprojectMetadata_DependencyGroup{
					{Name: "async", Dependencies: []string{"aiohttp", "fastapi"}},
					{Name: "dev", Dependencies: []string{"pytest", "black"}},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := pyprojecttoml.ToProto(tc.input)
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("ToProto(%v) returned unexpected diff (-want +got):\n%s", tc.input, diff)
			}

			gotStruct := pyprojecttoml.ToStruct(tc.want)
			if diff := cmp.Diff(tc.input, gotStruct, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("ToStruct(%v) returned unexpected diff (-want +got):\n%s", tc.want, diff)
			}
		})
	}
}
