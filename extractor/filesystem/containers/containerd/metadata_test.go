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

package containerd_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/containerd"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestSetProto(t *testing.T) {
	tests := []struct {
		desc string
		m    *containerd.Metadata
		p    *pb.Package
		want *pb.Package
	}{
		{
			desc: "nil metadata",
			m:    nil,
			p:    &pb.Package{Name: "some-package"},
			want: &pb.Package{Name: "some-package"},
		},
		{
			desc: "nil package",
			m: &containerd.Metadata{
				Namespace: "test-ns",
			},
			p:    nil,
			want: nil,
		},
		{
			desc: "set_metadata",
			m: &containerd.Metadata{
				Namespace: "test-ns",
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_ContainerdContainerMetadata{
					ContainerdContainerMetadata: &pb.ContainerdContainerMetadata{
						NamespaceName: "test-ns",
					},
				},
			},
		},
		{
			desc: "override_metadata",
			m: &containerd.Metadata{
				Namespace: "another-ns",
			},
			p: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_ContainerdContainerMetadata{
					ContainerdContainerMetadata: &pb.ContainerdContainerMetadata{
						NamespaceName: "test-ns",
					},
				},
			},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_ContainerdContainerMetadata{
					ContainerdContainerMetadata: &pb.ContainerdContainerMetadata{
						NamespaceName: "another-ns",
					},
				},
			},
		},
		{
			desc: "full metadata",
			m: &containerd.Metadata{
				Namespace:    "test-ns",
				ImageName:    "test-image",
				ImageDigest:  "sha256:123",
				Runtime:      "runc",
				ID:           "container-id",
				PodName:      "test-pod",
				PodNamespace: "pod-ns",
				PID:          1234,
				Snapshotter:  "overlayfs",
				SnapshotKey:  "sha256:456",
				LowerDir:     "/lower",
				UpperDir:     "/upper",
				WorkDir:      "/work",
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_ContainerdContainerMetadata{
					ContainerdContainerMetadata: &pb.ContainerdContainerMetadata{
						NamespaceName: "test-ns",
						ImageName:     "test-image",
						ImageDigest:   "sha256:123",
						Runtime:       "runc",
						Id:            "container-id",
						PodName:       "test-pod",
						PodNamespace:  "pod-ns",
						Pid:           1234,
						Snapshotter:   "overlayfs",
						SnapshotKey:   "sha256:456",
						LowerDir:      "/lower",
						UpperDir:      "/upper",
						WorkDir:       "/work",
					},
				},
			},
		},
	}

	for _, tc := range tests {
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

			got := containerd.ToStruct(p.GetContainerdContainerMetadata())
			if diff := cmp.Diff(tc.m, got); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", p.GetApkMetadata(), diff)
			}
		})
	}
}

func TestToStruct(t *testing.T) {
	tests := []struct {
		desc string
		m    *pb.ContainerdContainerMetadata
		want *containerd.Metadata
	}{
		{
			desc: "nil",
			m:    nil,
			want: nil,
		},
		{
			desc: "some_fields",
			m: &pb.ContainerdContainerMetadata{
				NamespaceName: "test-ns",
			},
			want: &containerd.Metadata{
				Namespace: "test-ns",
			},
		},
		{
			desc: "full metadata",
			m: &pb.ContainerdContainerMetadata{
				NamespaceName: "test-ns",
				ImageName:     "test-image",
				ImageDigest:   "sha256:123",
				Runtime:       "runc",
				Id:            "container-id",
				PodName:       "test-pod",
				PodNamespace:  "pod-ns",
				Pid:           1234,
				Snapshotter:   "overlayfs",
				SnapshotKey:   "sha256:456",
				LowerDir:      "/lower",
				UpperDir:      "/upper",
				WorkDir:       "/work",
			},
			want: &containerd.Metadata{
				Namespace:    "test-ns",
				ImageName:    "test-image",
				ImageDigest:  "sha256:123",
				Runtime:      "runc",
				ID:           "container-id",
				PodName:      "test-pod",
				PodNamespace: "pod-ns",
				PID:          1234,
				Snapshotter:  "overlayfs",
				SnapshotKey:  "sha256:456",
				LowerDir:     "/lower",
				UpperDir:     "/upper",
				WorkDir:      "/work",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := containerd.ToStruct(tc.m)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", tc.m, diff)
			}

			if tc.m == nil {
				return
			}

			// Test the reverse conversion for completeness.

			gotP := &pb.Package{}
			wantP := &pb.Package{
				Metadata: &pb.Package_ContainerdContainerMetadata{
					ContainerdContainerMetadata: tc.m,
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
