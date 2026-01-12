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
	"github.com/google/osv-scalibr/extractor/filesystem/os/kernel/module/metadata"
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
			m: &metadata.Metadata{
				PackageName: "package",
			},
			p:    nil,
			want: nil,
		},
		{
			desc: "set_metadata",
			m: &metadata.Metadata{
				PackageName: "package",
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_KernelModuleMetadata{
					KernelModuleMetadata: &pb.KernelModuleMetadata{
						PackageName: "package",
					},
				},
			},
		},
		{
			desc: "override_metadata",
			m: &metadata.Metadata{
				PackageName: "another-package",
			},
			p: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_KernelModuleMetadata{
					KernelModuleMetadata: &pb.KernelModuleMetadata{
						PackageName: "package",
					},
				},
			},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_KernelModuleMetadata{
					KernelModuleMetadata: &pb.KernelModuleMetadata{
						PackageName: "another-package",
					},
				},
			},
		},
		{
			desc: "set_all_fields",
			m: &metadata.Metadata{
				PackageName:                    "package",
				PackageVersion:                 "version",
				PackageVermagic:                "vermagic",
				PackageSourceVersionIdentifier: "source-version-identifier",
				OSID:                           "os-id",
				OSVersionCodename:              "os-version-codename",
				OSVersionID:                    "os-version-id",
				PackageAuthor:                  "author",
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_KernelModuleMetadata{
					KernelModuleMetadata: &pb.KernelModuleMetadata{
						PackageName:                    "package",
						PackageVersion:                 "version",
						PackageVermagic:                "vermagic",
						PackageSourceVersionIdentifier: "source-version-identifier",
						OsId:                           "os-id",
						OsVersionCodename:              "os-version-codename",
						OsVersionId:                    "os-version-id",
						PackageAuthor:                  "author",
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

			got := metadata.ToStruct(p.GetKernelModuleMetadata())
			if diff := cmp.Diff(tc.m, got); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", p.GetKernelModuleMetadata(), diff)
			}
		})
	}
}

func TestToStruct(t *testing.T) {
	testCases := []struct {
		desc string
		m    *pb.KernelModuleMetadata
		want *metadata.Metadata
	}{
		{
			desc: "nil",
			m:    nil,
			want: nil,
		},
		{
			desc: "some_fields",
			m: &pb.KernelModuleMetadata{
				PackageName: "package",
			},
			want: &metadata.Metadata{
				PackageName: "package",
			},
		},
		{
			desc: "all_fields",
			m: &pb.KernelModuleMetadata{
				PackageName:                    "package",
				PackageVersion:                 "version",
				PackageVermagic:                "vermagic",
				PackageSourceVersionIdentifier: "source-version-identifier",
				OsId:                           "os-id",
				OsVersionCodename:              "os-version-codename",
				OsVersionId:                    "os-version-id",
				PackageAuthor:                  "author",
			},
			want: &metadata.Metadata{
				PackageName:                    "package",
				PackageVersion:                 "version",
				PackageVermagic:                "vermagic",
				PackageSourceVersionIdentifier: "source-version-identifier",
				OSID:                           "os-id",
				OSVersionCodename:              "os-version-codename",
				OSVersionID:                    "os-version-id",
				PackageAuthor:                  "author",
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
				Metadata: &pb.Package_KernelModuleMetadata{
					KernelModuleMetadata: tc.m,
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
