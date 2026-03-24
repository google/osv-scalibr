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
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func TestToProto(t *testing.T) {
	testCases := []struct {
		desc string
		m    *metadata.Metadata
		want *pb.RPMPackageMetadata
	}{
		{
			desc: "set_metadata",
			m: &metadata.Metadata{
				PackageName: "name",
			},
			want: &pb.RPMPackageMetadata{
				PackageName: "name",
			},
		},
		{
			desc: "set_all_fields",
			m: &metadata.Metadata{
				PackageName:  "name",
				SourceRPM:    "source-rpm",
				Epoch:        1,
				OSName:       "os-name",
				OSPrettyName: "os-pretty-name",
				OSID:         "os-id",
				OSVersionID:  "os-version-id",
				OSBuildID:    "os-build-id",
				Vendor:       "vendor",
				Architecture: "architecture",
				OSCPEName:    "os-cpe-name",
			},
			want: &pb.RPMPackageMetadata{
				PackageName:  "name",
				SourceRpm:    "source-rpm",
				Epoch:        1,
				OsName:       "os-name",
				OsPrettyName: "os-pretty-name",
				OsId:         "os-id",
				OsVersionId:  "os-version-id",
				OsBuildId:    "os-build-id",
				Vendor:       "vendor",
				Architecture: "architecture",
				OsCpeName:    "os-cpe-name",
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
		m    *pb.RPMPackageMetadata
		want *metadata.Metadata
	}{
		{
			desc: "some_fields",
			m: &pb.RPMPackageMetadata{
				PackageName: "name",
			},
			want: &metadata.Metadata{
				PackageName: "name",
			},
		},
		{
			desc: "all_fields",
			m: &pb.RPMPackageMetadata{
				PackageName:  "name",
				SourceRpm:    "source-rpm",
				Epoch:        1,
				OsName:       "os-name",
				OsPrettyName: "os-pretty-name",
				OsId:         "os-id",
				OsVersionId:  "os-version-id",
				OsBuildId:    "os-build-id",
				Vendor:       "vendor",
				Architecture: "architecture",
				OsCpeName:    "os-cpe-name",
			},
			want: &metadata.Metadata{
				PackageName:  "name",
				SourceRPM:    "source-rpm",
				Epoch:        1,
				OSName:       "os-name",
				OSPrettyName: "os-pretty-name",
				OSID:         "os-id",
				OSVersionID:  "os-version-id",
				OSBuildID:    "os-build-id",
				Vendor:       "vendor",
				Architecture: "architecture",
				OSCPEName:    "os-cpe-name",
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

func TestOpenEulerEcosystemSuffix(t *testing.T) {
	testCases := []struct {
		desc string
		meta *metadata.Metadata
		want string
	}{
		{
			desc: "base_version_from_pretty_name",
			meta: &metadata.Metadata{
				OSPrettyName: "openEuler 24.03",
			},
			want: "24.03",
		},
		{
			desc: "lts_qualifier",
			meta: &metadata.Metadata{
				OSPrettyName: "openEuler 24.03 (LTS)",
			},
			want: "24.03-LTS",
		},
		{
			desc: "lts_space_qualifier",
			meta: &metadata.Metadata{
				OSPrettyName: "openEuler 24.03 (LTS SP1)",
			},
			want: "24.03-LTS-SP1",
		},
		{
			desc: "lts_hyphen_qualifier",
			meta: &metadata.Metadata{
				OSPrettyName: "openEuler 24.03 (LTS-SP1)",
			},
			want: "24.03-LTS-SP1",
		},
		{
			desc: "fallback_to_version_id",
			meta: &metadata.Metadata{
				OSVersionID: "24.03",
			},
			want: "24.03",
		},
		{
			desc: "non_openEuler_pretty_name",
			meta: &metadata.Metadata{
				OSPrettyName: "Fedora Linux 38 (Container Image)",
				OSVersionID:  "38",
			},
			want: "38",
		},
		{
			desc: "no_details",
			meta: &metadata.Metadata{},
			want: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			if got := tc.meta.OpenEulerEcosystemSuffix(); got != tc.want {
				t.Fatalf("OpenEulerEcosystemSuffix() = %q, want %q", got, tc.want)
			}
		})
	}
}
