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
	"github.com/google/osv-scalibr/extractor/filesystem/os/portage/metadata"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func TestToProto(t *testing.T) {
	testCases := []struct {
		desc string
		m    *metadata.Metadata
		want *pb.PortagePackageMetadata
	}{
		{
			desc: "set_metadata",
			m: &metadata.Metadata{
				PackageName: "name",
			},
			want: &pb.PortagePackageMetadata{
				PackageName: "name",
			},
		},
		{
			desc: "set_all_fields",
			m: &metadata.Metadata{
				PackageName:    "name",
				PackageVersion: "version",
				OSID:           "os-id",
				OSVersionID:    "os-version-id",
			},
			want: &pb.PortagePackageMetadata{
				PackageName:    "name",
				PackageVersion: "version",
				OsId:           "os-id",
				OsVersionId:    "os-version-id",
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
				t.Errorf("metadata.ToProto(%+v): (-want +got):\n%s", tc.m, diff)
			}

			// Test the reverse conversion for completeness.
			gotStruct := metadata.ToStruct(got)
			if diff := cmp.Diff(tc.m, gotStruct); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", got, diff)
			}
		})
	}
}

func TestToStruct(t *testing.T) {
	testCases := []struct {
		desc string
		m    *pb.PortagePackageMetadata
		want *metadata.Metadata
	}{
		{
			desc: "some_fields",
			m: &pb.PortagePackageMetadata{
				PackageName: "name",
			},
			want: &metadata.Metadata{
				PackageName: "name",
			},
		},
		{
			desc: "all_fields",
			m: &pb.PortagePackageMetadata{
				PackageName:    "name",
				PackageVersion: "version",
				OsId:           "os-id",
				OsVersionId:    "os-version-id",
			},
			want: &metadata.Metadata{
				PackageName:    "name",
				PackageVersion: "version",
				OSID:           "os-id",
				OSVersionID:    "os-version-id",
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
			gotProto := metadata.ToProto(got)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.m, gotProto, opts...); diff != "" {
				t.Errorf("metadata.ToProto(%+v): (-want +got):\n%s", got, diff)
			}
		})
	}
}
