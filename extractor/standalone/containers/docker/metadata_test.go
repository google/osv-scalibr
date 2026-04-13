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

package docker_test

import (
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/google/go-cmp/cmp"
	metadata "github.com/google/osv-scalibr/extractor/standalone/containers/docker"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

var (
	metadataStruct1 = &metadata.Metadata{
		ImageName:   "test-image-name",
		ImageDigest: "test-image-digest",
		ID:          "test-id",
		Ports: []container.Port{
			{
				IP:          "127.0.0.1",
				PrivatePort: 8080,
				PublicPort:  8080,
				Type:        "tcp",
			},
			{
				IP:          "127.0.0.1",
				PrivatePort: 8081,
				PublicPort:  8081,
				Type:        "udp",
			},
		},
	}
	metadataProto1 = &pb.DockerContainersMetadata{
		ImageName:   "test-image-name",
		ImageDigest: "test-image-digest",
		Id:          "test-id",
		Ports: []*pb.DockerPort{
			{
				Ip:          "127.0.0.1",
				PrivatePort: 8080,
				PublicPort:  8080,
				Type:        "tcp",
			},
			{
				Ip:          "127.0.0.1",
				PrivatePort: 8081,
				PublicPort:  8081,
				Type:        "udp",
			},
		},
	}
)

func TestToProto(t *testing.T) {
	testCases := []struct {
		desc string
		m    *metadata.Metadata
		want *pb.DockerContainersMetadata
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
		m    *pb.DockerContainersMetadata
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
