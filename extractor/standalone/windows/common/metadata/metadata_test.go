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
	"github.com/google/osv-scalibr/extractor/standalone/windows/common/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

var (
	metadataStruct1 = &metadata.OSVersion{
		Product:     "windows_server_2019",
		FullVersion: "10.0.17763.3793",
	}
	metadataProto1 = &pb.WindowsOSVersion{
		Product:     "windows_server_2019",
		FullVersion: "10.0.17763.3793",
	}
)

func TestSetProto(t *testing.T) {
	testCases := []struct {
		desc string
		m    *metadata.OSVersion
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
			m:    metadataStruct1,
			p:    nil,
			want: nil,
		},
		{
			desc: "set_metadata",
			m:    metadataStruct1,
			p:    &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_WindowsOsVersionMetadata{
					WindowsOsVersionMetadata: metadataProto1,
				},
			},
		},
		{
			desc: "override_metadata",
			m: &metadata.OSVersion{
				Product:     "other-windows_server_2022",
				FullVersion: "77.7.7777.7777",
			},
			p: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_WindowsOsVersionMetadata{
					WindowsOsVersionMetadata: metadataProto1,
				},
			},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_WindowsOsVersionMetadata{
					WindowsOsVersionMetadata: &pb.WindowsOSVersion{
						Product:     "other-windows_server_2022",
						FullVersion: "77.7.7777.7777",
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

			got := metadata.ToStruct(p.GetWindowsOsVersionMetadata())
			if diff := cmp.Diff(tc.m, got); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", p.GetWindowsOsVersionMetadata(), diff)
			}
		})
	}
}

func TestToStruct(t *testing.T) {
	testCases := []struct {
		desc string
		m    *pb.WindowsOSVersion
		want *metadata.OSVersion
	}{
		{
			desc: "nil",
			m:    nil,
			want: nil,
		},
		{
			desc: "all_fields",
			m:    metadataProto1,
			want: metadataStruct1,
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
				Metadata: &pb.Package_WindowsOsVersionMetadata{
					WindowsOsVersionMetadata: tc.m,
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
