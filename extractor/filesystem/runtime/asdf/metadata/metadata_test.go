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

package metadata_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/filesystem/runtime/asdf/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func TestSetProto(t *testing.T) {
	testCases := []struct {
		desc string
		m    *metadata.Metadata
		p    *pb.Package
		want *pb.Package
	}{
		{
			desc: "nil metadata",
			m:    nil,
			p:    &pb.Package{Name: "some-package"},
			want: &pb.Package{Name: "some-package"},
		},
		{
			desc: "nil package",
			m: &metadata.Metadata{
				ToolName: "name",
			},
			p:    nil,
			want: nil,
		},
		{
			desc: "set metadata",
			m: &metadata.Metadata{
				ToolName: "name",
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_AsdfMetadata{
					AsdfMetadata: &pb.AsdfMetadata{
						ToolName: "name",
					},
				},
			},
		},
		{
			desc: "override metadata",
			m: &metadata.Metadata{
				ToolName: "another-name",
			},
			p: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_AsdfMetadata{
					AsdfMetadata: &pb.AsdfMetadata{
						ToolName: "name",
					},
				},
			},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_AsdfMetadata{
					AsdfMetadata: &pb.AsdfMetadata{
						ToolName: "another-name",
					},
				},
			},
		},
		{
			desc: "set all fields",
			m: &metadata.Metadata{
				ToolName:    "name",
				ToolVersion: "version",
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_AsdfMetadata{
					AsdfMetadata: &pb.AsdfMetadata{
						ToolName:    "name",
						ToolVersion: "version",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			p := proto.Clone(tc.p).(*pb.Package)
			tc.m.SetProto(p)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.want, p, opts...); diff != "" {
				t.Errorf("Metatadata{%+v}.SetProto(%+v): (-want +got):\n%s", tc.m, tc.p, diff)
			}

			// Test the reverse conversion for completeness.

			if tc.p == nil && tc.want == nil {
				return
			}

			got := metadata.ToStruct(p.GetAsdfMetadata())
			if diff := cmp.Diff(tc.m, got); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", p.GetAsdfMetadata(), diff)
			}
		})
	}
}

func TestToStruct(t *testing.T) {
	testCases := []struct {
		desc string
		m    *pb.AsdfMetadata
		want *metadata.Metadata
	}{
		{
			desc: "nil",
			m:    nil,
			want: nil,
		},
		{
			desc: "some fields",
			m: &pb.AsdfMetadata{
				ToolName: "name",
			},
			want: &metadata.Metadata{
				ToolName: "name",
			},
		},
		{
			desc: "all fields",
			m: &pb.AsdfMetadata{
				ToolName:    "name",
				ToolVersion: "version",
			},
			want: &metadata.Metadata{
				ToolName:    "name",
				ToolVersion: "version",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := metadata.ToStruct(tc.m)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", tc.m, diff)
			}

			if tc.m == nil {
				return
			}

			// Test the reverse conversion for completeness.

			gotP := &pb.Package{}
			wantP := &pb.Package{
				Metadata: &pb.Package_AsdfMetadata{
					AsdfMetadata: tc.m,
				},
			}
			got.SetProto(gotP)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(wantP, gotP, opts...); diff != "" {
				t.Errorf("Metatadata{%+v}.SetProto(%+v): (-want +got):\n%s", got, wantP, diff)
			}
		})
	}
}
