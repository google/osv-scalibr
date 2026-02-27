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

package depsjson_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/depsjson"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func TestToProto(t *testing.T) {
	testCases := []struct {
		desc string
		m    *depsjson.Metadata
		want *pb.DEPSJSONMetadata
	}{
		{
			desc: "set_metadata",
			m:    &depsjson.Metadata{PackageName: "some-package"},
			want: &pb.DEPSJSONMetadata{
				PackageName: "some-package",
			},
		},
		{
			desc: "set_all_fields",
			m: &depsjson.Metadata{
				PackageName:    "some-package",
				PackageVersion: "1.0.0",
				Type:           "package",
			},
			want: &pb.DEPSJSONMetadata{
				PackageName:    "some-package",
				PackageVersion: "1.0.0",
				Type:           "package",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := depsjson.ToProto(tc.m)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.want, got, opts...); diff != "" {
				t.Errorf("depsjson.ToProto(%+v): (-want +got):\n%s", tc.m, diff)
			}

			// Test the reverse conversion for completeness.
			gotStruct := depsjson.ToStruct(got)
			if diff := cmp.Diff(tc.m, gotStruct); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", got, diff)
			}
		})
	}
}

func TestToStruct(t *testing.T) {
	testCases := []struct {
		desc string
		m    *pb.DEPSJSONMetadata
		want *depsjson.Metadata
	}{

		{
			desc: "some_fields",
			m: &pb.DEPSJSONMetadata{
				PackageName: "some-package",
			},
			want: &depsjson.Metadata{
				PackageName: "some-package",
			},
		},
		{
			desc: "all_fields",
			m: &pb.DEPSJSONMetadata{
				PackageName:    "some-package",
				PackageVersion: "1.0.0",
				Type:           "package",
			},
			want: &depsjson.Metadata{
				PackageName:    "some-package",
				PackageVersion: "1.0.0",
				Type:           "package",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := depsjson.ToStruct(tc.m)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", tc.m, diff)
			}

			// Test the reverse conversion for completeness.
			gotProto := depsjson.ToProto(got)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.m, gotProto, opts...); diff != "" {
				t.Errorf("depsjson.ToProto(%+v): (-want +got):\n%s", got, diff)
			}
		})
	}
}
