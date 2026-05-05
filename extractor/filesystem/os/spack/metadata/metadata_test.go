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
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func TestToProto(t *testing.T) {
	testCases := []struct {
		desc string
		m    *metadata.Metadata
		want *pb.SpackPackageMetadata
	}{
		{
			desc: "simple_metadata",
			m: &metadata.Metadata{
				Platform: "linux",
			},
			want: &pb.SpackPackageMetadata{
				Platform: "linux",
			},
		},
		{
			desc: "all_fields",
			m: &metadata.Metadata{
				Hash:         "dsohcyk45wchbd364rjio7b3sj2bucgc",
				Platform:     "linux",
				PlatformOS:   "ubuntu24.04",
				Architecture: "skylake",
			},
			want: &pb.SpackPackageMetadata{
				Hash:                 "dsohcyk45wchbd364rjio7b3sj2bucgc",
				Platform:             "linux",
				PlatformOs:           "ubuntu24.04",
				PlatformArchitecture: "skylake",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := metadata.ToProto(tc.m)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.want, got, opts...); diff != "" {
				t.Errorf("ToProto(%+v): (-want +got):\n%s", tc.m, diff)
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
		})
	}
}
