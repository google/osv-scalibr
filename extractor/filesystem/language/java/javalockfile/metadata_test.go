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

package javalockfile_test

import (
	"testing"

	"deps.dev/util/maven"
	"github.com/google/go-cmp/cmp"
	metadata "github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

var (
	metadataStruct1 = &metadata.Metadata{
		ArtifactID:   "artifact-id",
		GroupID:      "group-id",
		DepGroupVals: []string{"dep-group-val"},
		IsTransitive: true,
	}
	metadataProto1 = &pb.JavaLockfileMetadata{
		ArtifactId:   "artifact-id",
		GroupId:      "group-id",
		DepGroupVals: []string{"dep-group-val"},
		IsTransitive: true,
	}
)

func TestToProto(t *testing.T) {
	testCases := []struct {
		desc string
		m    *metadata.Metadata
		want *pb.JavaLockfileMetadata
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
		m    *pb.JavaLockfileMetadata
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

			if tc.m == nil {
				return
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

func TestDependenciesToProto(t *testing.T) {
	testCases := []struct {
		desc string
		deps []maven.Dependency
		want []*pb.JavaLockfileDependency
	}{
		{
			desc: "empty",
			deps: nil,
			want: nil,
		},
		{
			desc: "single",
			deps: []maven.Dependency{
				{
					GroupID:    "group-id",
					ArtifactID: "artifact-id",
					Version:    "1.0.0",
					Scope:      "compile",
					Optional:   "true",
				},
			},
			want: []*pb.JavaLockfileDependency{
				{
					GroupId:            "group-id",
					ArtifactId:         "artifact-id",
					VersionRequirement: "1.0.0",
					Scope:              "compile",
					IsOptional:         true,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := metadata.DependenciesToProto(tc.deps)
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("DependenciesToProto(%+v): (-want +got):\n%s", tc.deps, diff)
			}

			// Test the reverse conversion for completeness.
			gotStruct := metadata.DependenciesToStruct(got)
			if diff := cmp.Diff(tc.deps, gotStruct); diff != "" {
				t.Errorf("DependenciesToStruct(%+v): (-want +got):\n%s", got, diff)
			}
		})
	}
}

func TestDependenciesToStruct(t *testing.T) {
	testCases := []struct {
		desc string
		deps []*pb.JavaLockfileDependency
		want []maven.Dependency
	}{
		{
			desc: "empty",
			deps: nil,
			want: nil,
		},
		{
			desc: "single",
			deps: []*pb.JavaLockfileDependency{
				{
					GroupId:            "group-id",
					ArtifactId:         "artifact-id",
					VersionRequirement: "1.0.0",
					Scope:              "compile",
					IsOptional:         true,
				},
			},
			want: []maven.Dependency{
				{
					GroupID:    "group-id",
					ArtifactID: "artifact-id",
					Version:    "1.0.0",
					Scope:      "compile",
					Optional:   "true",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := metadata.DependenciesToStruct(tc.deps)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("DependenciesToStruct(%+v): (-want +got):\n%s", tc.deps, diff)
			}

			// Test the reverse conversion for completeness.
			gotProto := metadata.DependenciesToProto(got)
			if diff := cmp.Diff(tc.deps, gotProto, protocmp.Transform()); diff != "" {
				t.Errorf("DependenciesToProto(%+v): (-want +got):\n%s", got, diff)
			}
		})
	}
}

func TestParentToProto(t *testing.T) {
	testCases := []struct {
		desc   string
		parent *maven.ProjectKey
		want   *pb.JavaLockfileParent
	}{
		{
			desc:   "nil",
			parent: nil,
			want:   nil,
		},
		{
			desc: "single",
			parent: &maven.ProjectKey{
				GroupID:    "group-id",
				ArtifactID: "artifact-id",
				Version:    "1.0.0",
			},
			want: &pb.JavaLockfileParent{
				GroupId:    "group-id",
				ArtifactId: "artifact-id",
				Version:    "1.0.0",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := metadata.ParentToProto(tc.parent)
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("ParentToProto(%+v): (-want +got):\n%s", tc.parent, diff)
			}

			// Test the reverse conversion for completeness.
			gotStruct := metadata.ParentToStruct(got)
			if diff := cmp.Diff(tc.parent, gotStruct); diff != "" {
				t.Errorf("ParentToStruct(%+v): (-want +got):\n%s", got, diff)
			}
		})
	}
}

func TestParentToStruct(t *testing.T) {
	testCases := []struct {
		desc   string
		parent *pb.JavaLockfileParent
		want   *maven.ProjectKey
	}{
		{
			desc:   "nil",
			parent: nil,
			want:   nil,
		},
		{
			desc: "single",
			parent: &pb.JavaLockfileParent{
				GroupId:    "group-id",
				ArtifactId: "artifact-id",
				Version:    "1.0.0",
			},
			want: &maven.ProjectKey{
				GroupID:    "group-id",
				ArtifactID: "artifact-id",
				Version:    "1.0.0",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := metadata.ParentToStruct(tc.parent)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ParentToStruct(%+v): (-want +got):\n%s", tc.parent, diff)
			}

			// Test the reverse conversion for completeness.
			gotProto := metadata.ParentToProto(got)
			if diff := cmp.Diff(tc.parent, gotProto, protocmp.Transform()); diff != "" {
				t.Errorf("ParentToProto(%+v): (-want +got):\n%s", got, diff)
			}
		})
	}
}
