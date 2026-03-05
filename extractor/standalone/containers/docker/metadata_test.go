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
	"google.golang.org/protobuf/proto"
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
				Metadata: &pb.Package_DockerContainersMetadata{
					DockerContainersMetadata: metadataProto1,
				},
			},
		},
		{
			desc: "override_metadata",
			m: &metadata.Metadata{
				ImageName:   "test-image-name-2",
				ImageDigest: "test-image-digest-2",
				ID:          "test-id-2",
				Ports: []container.Port{
					{
						IP:          "127.0.0.2",
						PrivatePort: 8082,
						PublicPort:  8082,
						Type:        "tcp",
					},
					{
						IP:          "127.0.0.2",
						PrivatePort: 8083,
						PublicPort:  8083,
						Type:        "udp",
					},
				},
			},
			p: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_DockerContainersMetadata{
					DockerContainersMetadata: metadataProto1,
				},
			},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_DockerContainersMetadata{
					DockerContainersMetadata: &pb.DockerContainersMetadata{
						ImageName:   "test-image-name-2",
						ImageDigest: "test-image-digest-2",
						Id:          "test-id-2",
						Ports: []*pb.DockerPort{
							{
								Ip:          "127.0.0.2",
								PrivatePort: 8082,
								PublicPort:  8082,
								Type:        "tcp",
							},
							{
								Ip:          "127.0.0.2",
								PrivatePort: 8083,
								PublicPort:  8083,
								Type:        "udp",
							},
						},
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

			got := metadata.ToStruct(p.GetDockerContainersMetadata())
			if diff := cmp.Diff(tc.m, got); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", p.GetDockerContainersMetadata(), diff)
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
				Metadata: &pb.Package_DockerContainersMetadata{
					DockerContainersMetadata: tc.m,
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
