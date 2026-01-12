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
	"github.com/google/osv-scalibr/extractor/filesystem/os/kernel/vmlinuz/metadata"
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
	}{{
		desc: "nil metadata",
		m:    nil,
		p:    &pb.Package{Name: "some-package"},
		want: &pb.Package{Name: "some-package"},
	}, {
		desc: "nil package",
		m: &metadata.Metadata{
			Name: "vmlinuz-5.10.0-0.deb10.16-amd64",
		},
		p:    nil,
		want: nil,
	}, {
		desc: "set metadata",
		m: &metadata.Metadata{
			Name: "vmlinuz-5.10.0-0.deb10.16-amd64",
		},
		p: &pb.Package{Name: "some-package"},
		want: &pb.Package{
			Name: "some-package",
			Metadata: &pb.Package_VmlinuzMetadata{
				VmlinuzMetadata: &pb.VmlinuzMetadata{
					Name: "vmlinuz-5.10.0-0.deb10.16-amd64",
				},
			},
		},
	}, {
		desc: "override metadata",
		m: &metadata.Metadata{
			Name: "vmlinuz-6.1.0-0.deb11.6-amd64",
		},
		p: &pb.Package{
			Name: "some-package",
			Metadata: &pb.Package_VmlinuzMetadata{
				VmlinuzMetadata: &pb.VmlinuzMetadata{
					Name: "vmlinuz-5.10.0-0.deb10.16-amd64",
				},
			},
		},
		want: &pb.Package{
			Name: "some-package",
			Metadata: &pb.Package_VmlinuzMetadata{
				VmlinuzMetadata: &pb.VmlinuzMetadata{
					Name: "vmlinuz-6.1.0-0.deb11.6-amd64",
				},
			},
		},
	}, {
		desc: "set all fields",
		m: &metadata.Metadata{
			Name:              "vmlinuz-5.10.0-0.deb10.16-amd64",
			Version:           "5.10.0-0.deb10.16-amd64",
			Architecture:      "amd64",
			ExtendedVersion:   "5.10.0-0.deb10.16-amd64 (Debian 5.10.127-1~deb10u1)",
			Format:            "vmlinuz",
			SwapDevice:        123,
			RootDevice:        456,
			VideoMode:         "normal",
			OSID:              "debian",
			OSVersionCodename: "buster",
			OSVersionID:       "10",
			RWRootFS:          true,
		},
		p: &pb.Package{Name: "some-package"},
		want: &pb.Package{
			Name: "some-package",
			Metadata: &pb.Package_VmlinuzMetadata{
				VmlinuzMetadata: &pb.VmlinuzMetadata{
					Name:              "vmlinuz-5.10.0-0.deb10.16-amd64",
					Version:           "5.10.0-0.deb10.16-amd64",
					Architecture:      "amd64",
					ExtendedVersion:   "5.10.0-0.deb10.16-amd64 (Debian 5.10.127-1~deb10u1)",
					Format:            "vmlinuz",
					SwapDevice:        123,
					RootDevice:        456,
					VideoMode:         "normal",
					OsId:              "debian",
					OsVersionCodename: "buster",
					OsVersionId:       "10",
					RwRootFs:          true,
				},
			},
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			p := proto.Clone(tc.p).(*pb.Package)
			tc.m.SetProto(p)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.want, p, opts...); diff != "" {
				t.Errorf("Metadata{%+v}.SetProto(%+v) returned diff (-want +got):\n%s", tc.m, tc.p, diff)
			}

			// Test the reverse conversion for completeness.
			if tc.m == nil || p == nil {
				return
			}
			got := metadata.ToStruct(p.GetVmlinuzMetadata())
			if diff := cmp.Diff(tc.m, got); diff != "" {
				t.Errorf("ToStruct(%+v) returned diff (-want +got):\n%s", p, diff)
			}
		})
	}
}

func TestToStruct(t *testing.T) {
	testCases := []struct {
		name string
		m    *pb.VmlinuzMetadata
		want *metadata.Metadata
	}{
		{
			name: "nil",
			m:    nil,
			want: nil,
		},
		{
			name: "some fields",
			m: &pb.VmlinuzMetadata{
				Name: "vmlinuz-5.10.0-0.deb10.16-amd64",
			},
			want: &metadata.Metadata{
				Name: "vmlinuz-5.10.0-0.deb10.16-amd64",
			},
		},
		{
			name: "all fields",
			m: &pb.VmlinuzMetadata{
				Name:              "vmlinuz-5.10.0-0.deb10.16-amd64",
				Version:           "5.10.0-0.deb10.16-amd64",
				Architecture:      "amd64",
				ExtendedVersion:   "5.10.0-0.deb10.16-amd64 (Debian 5.10.127-1~deb10u1)",
				Format:            "vmlinuz",
				SwapDevice:        123,
				RootDevice:        456,
				VideoMode:         "normal",
				OsId:              "debian",
				OsVersionCodename: "buster",
				OsVersionId:       "10",
				RwRootFs:          true,
			},
			want: &metadata.Metadata{
				Name:              "vmlinuz-5.10.0-0.deb10.16-amd64",
				Version:           "5.10.0-0.deb10.16-amd64",
				Architecture:      "amd64",
				ExtendedVersion:   "5.10.0-0.deb10.16-amd64 (Debian 5.10.127-1~deb10u1)",
				Format:            "vmlinuz",
				SwapDevice:        123,
				RootDevice:        456,
				VideoMode:         "normal",
				OSID:              "debian",
				OSVersionCodename: "buster",
				OSVersionID:       "10",
				RWRootFS:          true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := metadata.ToStruct(tc.m)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ToStruct(%+v) returned diff (-want +got):\n%s", tc.m, diff)
			}

			if tc.want == nil {
				return
			}

			// Test the reverse conversion for completeness.
			gotP := &pb.Package{}
			wantP := &pb.Package{
				Metadata: &pb.Package_VmlinuzMetadata{
					VmlinuzMetadata: tc.m,
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
