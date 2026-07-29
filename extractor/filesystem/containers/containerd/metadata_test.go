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

package containerd_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/containerd"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestToProto(t *testing.T) {
	tests := []struct {
		desc string
		m    *containerd.Metadata
		want *pb.ContainerdContainerMetadata
	}{
		{
			desc: "set_metadata",
			m: &containerd.Metadata{
				Namespace: "test-ns",
			},
			want: &pb.ContainerdContainerMetadata{
				NamespaceName: "test-ns",
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
			want: &pb.ContainerdContainerMetadata{
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
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := containerd.ToProto(tc.m)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.want, got, opts...); diff != "" {
				t.Errorf("containerd.ToProto(%+v): (-want +got):\n%s", tc.m, diff)
			}

			// Test the reverse conversion for completeness.
			gotStruct := containerd.ToStruct(got)
			if diff := cmp.Diff(tc.m, gotStruct); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", got, diff)
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

			// Test the reverse conversion for completeness.
			gotProto := containerd.ToProto(got)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.m, gotProto, opts...); diff != "" {
				t.Errorf("containerd.ToProto(%+v): (-want +got):\n%s", got, diff)
			}
		})
	}
}
