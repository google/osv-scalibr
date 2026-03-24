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

package netports_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/standalone/os/netports"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func TestToProto(t *testing.T) {
	testCases := []struct {
		desc string
		m    *netports.Metadata
		want *pb.NetportsMetadata
	}{
		{
			desc: "set_metadata",
			m: &netports.Metadata{
				Port: 8080,
			},
			want: &pb.NetportsMetadata{
				Port: 8080,
			},
		},
		{
			desc: "set_all_fields",
			m: &netports.Metadata{
				Port:     8080,
				Protocol: "tcp",
				Cmdline:  "some-command-line",
			},
			want: &pb.NetportsMetadata{
				Port:        8080,
				Protocol:    "tcp",
				CommandLine: "some-command-line",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := netports.ToProto(tc.m)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.want, got, opts...); diff != "" {
				t.Errorf("netports.ToProto(%+v): (-want +got):\n%s", tc.m, diff)
			}

			// Test the reverse conversion for completeness.
			gotStruct := netports.ToStruct(got)
			if diff := cmp.Diff(tc.m, gotStruct); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", got, diff)
			}
		})
	}
}

func TestToStruct(t *testing.T) {
	testCases := []struct {
		desc string
		m    *pb.NetportsMetadata
		want *netports.Metadata
	}{
		{
			desc: "some_fields",
			m: &pb.NetportsMetadata{
				Port: 8080,
			},
			want: &netports.Metadata{
				Port: 8080,
			},
		},
		{
			desc: "all_fields",
			m: &pb.NetportsMetadata{
				Port:        8080,
				Protocol:    "tcp",
				CommandLine: "some-command-line",
			},
			want: &netports.Metadata{
				Port:     8080,
				Protocol: "tcp",
				Cmdline:  "some-command-line",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := netports.ToStruct(tc.m)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", tc.m, diff)
			}

			if tc.m == nil {
				return
			}

			// Test the reverse conversion for completeness.
			gotProto := netports.ToProto(got)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.m, gotProto, opts...); diff != "" {
				t.Errorf("netports.ToProto(%+v): (-want +got):\n%s", got, diff)
			}
		})
	}
}
