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

package metadata_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/filesystem/os/spack/metadata"
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
			desc: "nil_metadata",
			m:    nil,
			p:    &pb.Package{Name: "some-package"},
			want: &pb.Package{Name: "some-package"},
		},
		{
			desc: "nil_package",
			m:    &metadata.Metadata{},
			p:    nil,
			want: nil,
		},
		{
			desc: "set_metadata",
			m: &metadata.Metadata{
				Platform: "linux",
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_SpackMetadata{
					SpackMetadata: &pb.SpackPackageMetadata{
						Platform: "linux",
					},
				},
			},
		},
		{
			desc: "override_metadata",
			m: &metadata.Metadata{
				Platform: "linux",
			},
			p: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_SpackMetadata{
					SpackMetadata: &pb.SpackPackageMetadata{
						Platform: "linux",
					},
				},
			},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_SpackMetadata{
					SpackMetadata: &pb.SpackPackageMetadata{
						Platform: "linux",
					},
				},
			},
		},
		{
			desc: "set_all_fields",
			m: &metadata.Metadata{
				Hash:         "dsohcyk45wchbd364rjio7b3sj2bucgc",
				Platform:     "linux",
				PlatformOS:   "ubuntu24.04",
				Architecture: "skylake",
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_SpackMetadata{
					SpackMetadata: &pb.SpackPackageMetadata{
						Hash:                 "dsohcyk45wchbd364rjio7b3sj2bucgc",
						Platform:             "linux",
						PlatformOs:           "ubuntu24.04",
						PlatformArchitecture: "skylake",
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
				t.Errorf("Metadata{%+v}.SetProto(%+v): (-want +got):\n%s", tc.m, tc.p, diff)
			}

			// Test the reverse conversion for completeness.
			if tc.p == nil && tc.want == nil {
				return
			}

			got := metadata.ToStruct(p.GetSpackMetadata())
			if diff := cmp.Diff(tc.m, got); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", p.GetSpackMetadata(), diff)
			}
		})
	}
}

func TestToStruct(t *testing.T) {
	testCases := []struct {
		desc string
		m    *pb.SpackPackageMetadata
		want *metadata.Metadata
	}{
		{
			desc: "nil",
			m:    nil,
			want: nil,
		},
		{
			desc: "some_fields",
			m: &pb.SpackPackageMetadata{
				Platform: "linux",
			},
			want: &metadata.Metadata{
				Platform: "linux",
			},
		},
		{
			desc: "all_fields",
			m: &pb.SpackPackageMetadata{
				Hash:                 "dsohcyk45wchbd364rjio7b3sj2bucgc",
				Platform:             "linux",
				PlatformOs:           "ubuntu24.04",
				PlatformArchitecture: "skylake",
			},
			want: &metadata.Metadata{
				Hash:         "dsohcyk45wchbd364rjio7b3sj2bucgc",
				Platform:     "linux",
				PlatformOS:   "ubuntu24.04",
				Architecture: "skylake",
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
				Metadata: &pb.Package_SpackMetadata{
					SpackMetadata: tc.m,
				},
			}
			got.SetProto(gotP)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(wantP, gotP, opts...); diff != "" {
				t.Errorf("Metadata{%+v}.SetProto(%+v): (-want +got):\n%s", got, gotP, diff)
			}
		})
	}
}
