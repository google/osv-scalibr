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

package convert_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/depsjson"
	"github.com/google/osv-scalibr/internal/proto/packagemetadata"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func TestSetProto(t *testing.T) {
	testCases := []struct {
		desc string
		p    *pb.Package
		m    any
		want *pb.Package
	}{
		{
			desc: "filesystem/language/dotnet/depsjson/depsjson/nil",
			p:    &pb.Package{},
			m:    nil,
			want: &pb.Package{},
		},
		{
			desc: "filesystem/language/dotnet/depsjson/depsjson",
			p:    &pb.Package{},
			m: &depsjson.Metadata{
				PackageName: "test",
			},
			want: &pb.Package{
				Metadata: &pb.Package_DepsjsonMetadata{
					DepsjsonMetadata: &pb.DEPSJSONMetadata{
						PackageName: "test",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			packagemetadata.SetProto(tc.p, tc.m)
			if diff := cmp.Diff(tc.want, tc.p, protocmp.Transform()); diff != "" {
				t.Errorf("SetProto(%v, %v) returned an unexpected diff (-want +got): %v", tc.p, tc.m, diff)
			}
		})
	}
}

func TestToStruct(t *testing.T) {
	testCases := []struct {
		desc string
		p    *pb.Package
		want any
	}{
		{
			desc: "filesystem/language/dotnet/depsjson/depsjson",
			p: &pb.Package{
				Metadata: &pb.Package_DepsjsonMetadata{
					DepsjsonMetadata: &pb.DEPSJSONMetadata{
						PackageName: "test",
					},
				},
			},
			want: &depsjson.Metadata{
				PackageName: "test",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := packagemetadata.ToStruct(tc.p)
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("ToStruct(%v) returned an unexpected diff (-want +got): %v", tc.p, diff)
			}
		})
	}
}
