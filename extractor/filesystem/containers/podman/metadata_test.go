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

package podman_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	metadata "github.com/google/osv-scalibr/extractor/filesystem/containers/podman"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

var (
	ts1  = time.Date(2023, time.January, 1, 2, 3, 4, 5, time.UTC)
	tpb1 = timestamppb.New(ts1)
	ts2  = time.Date(2024, time.February, 4, 5, 6, 7, 8, time.UTC)
	tpb2 = timestamppb.New(ts2)

	metadataStruct1 = &metadata.Metadata{
		ExposedPorts: map[uint16][]string{
			8080: []string{"tcp", "udp"},
			8081: []string{"tcp"},
		},
		PID:          12345,
		NameSpace:    "test-namespace",
		StartedTime:  ts1,
		FinishedTime: ts2,
		Status:       "running",
		ExitCode:     2,
		Exited:       true,
	}
	metadataProto1 = &pb.PodmanMetadata{
		ExposedPorts: map[uint32]*pb.Protocol{
			8080: &pb.Protocol{Names: []string{"tcp", "udp"}},
			8081: &pb.Protocol{Names: []string{"tcp"}},
		},
		Pid:           12345,
		NamespaceName: "test-namespace",
		StartedTime:   tpb1,
		FinishedTime:  tpb2,
		Status:        "running",
		ExitCode:      2,
		Exited:        true,
	}
)

func TestToProto(t *testing.T) {
	testCases := []struct {
		desc string
		m    *metadata.Metadata
		want *pb.PodmanMetadata
	}{
		{
			desc: "set_metadata",
			m:    metadataStruct1,
			want: metadataProto1,
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
		m    *pb.PodmanMetadata
		want *metadata.Metadata
	}{

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
