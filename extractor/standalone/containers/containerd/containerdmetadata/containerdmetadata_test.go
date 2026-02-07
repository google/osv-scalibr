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

package containerdmetadata_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	metadata "github.com/google/osv-scalibr/extractor/standalone/containers/containerd/containerdmetadata"
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
			Namespace: "some-namespace",
		},
		p:    nil,
		want: nil,
	}, {
		desc: "set metadata",
		m: &metadata.Metadata{
			Namespace: "some-namespace",
		},
		p: &pb.Package{Name: "some-package"},
		want: &pb.Package{
			Name: "some-package",
			Metadata: &pb.Package_ContainerdRuntimeContainerMetadata{
				ContainerdRuntimeContainerMetadata: &pb.ContainerdRuntimeContainerMetadata{
					NamespaceName: "some-namespace",
				},
			},
		},
	}, {
		desc: "override metadata",
		m: &metadata.Metadata{
			Namespace: "some-namespace",
		},
		p: &pb.Package{
			Name: "some-package",
			Metadata: &pb.Package_ContainerdRuntimeContainerMetadata{
				ContainerdRuntimeContainerMetadata: &pb.ContainerdRuntimeContainerMetadata{
					NamespaceName: "some-other-namespace",
				},
			},
		},
		want: &pb.Package{
			Name: "some-package",
			Metadata: &pb.Package_ContainerdRuntimeContainerMetadata{
				ContainerdRuntimeContainerMetadata: &pb.ContainerdRuntimeContainerMetadata{
					NamespaceName: "some-namespace",
				},
			},
		},
	}, {
		desc: "set all fields",
		m: &metadata.Metadata{
			Namespace:   "namespace",
			ImageName:   "image-name",
			ImageDigest: "image-digest",
			Runtime:     "runtime",
			ID:          "id",
			PID:         123,
			RootFS:      "/some/root/fs",
		},
		p: &pb.Package{Name: "some-package"},
		want: &pb.Package{
			Name: "some-package",
			Metadata: &pb.Package_ContainerdRuntimeContainerMetadata{
				ContainerdRuntimeContainerMetadata: &pb.ContainerdRuntimeContainerMetadata{
					NamespaceName: "namespace",
					ImageName:     "image-name",
					ImageDigest:   "image-digest",
					Runtime:       "runtime",
					Id:            "id",
					Pid:           123,
					RootfsPath:    "/some/root/fs",
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
			got := metadata.ToStruct(p.GetContainerdRuntimeContainerMetadata())
			if diff := cmp.Diff(tc.m, got); diff != "" {
				t.Errorf("ToStruct(%+v) returned diff (-want +got):\n%s", p, diff)
			}
		})
	}
}

func TestToStruct(t *testing.T) {
	testCases := []struct {
		name string
		m    *pb.ContainerdRuntimeContainerMetadata
		want *metadata.Metadata
	}{
		{
			name: "nil",
			m:    nil,
			want: nil,
		},
		{
			name: "some fields",
			m: &pb.ContainerdRuntimeContainerMetadata{
				NamespaceName: "namespace",
			},
			want: &metadata.Metadata{
				Namespace: "namespace",
			},
		},
		{
			name: "all fields",
			m: &pb.ContainerdRuntimeContainerMetadata{
				NamespaceName: "namespace",
				ImageName:     "image-name",
				ImageDigest:   "image-digest",
				Runtime:       "runtime",
				Id:            "id",
				Pid:           123,
				RootfsPath:    "/some/root/fs",
			},
			want: &metadata.Metadata{
				Namespace:   "namespace",
				ImageName:   "image-name",
				ImageDigest: "image-digest",
				Runtime:     "runtime",
				ID:          "id",
				PID:         123,
				RootFS:      "/some/root/fs",
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
				Metadata: &pb.Package_ContainerdRuntimeContainerMetadata{
					ContainerdRuntimeContainerMetadata: tc.m,
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
