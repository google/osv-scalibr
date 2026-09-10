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

package proto_test

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/binary/proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
	"google.golang.org/protobuf/testing/protocmp"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

var (
	pkgOpts = []cmp.Option{
		// Ignore the non-deterministic ID and the legacy location field.
		protocmp.IgnoreFields(&spb.Package{}, "id", "locations"),
	}
)

func exampleTransitiveDependencyPackage() *extractor.Package {
	return &extractor.Package{
		Name:      "transitive_package",
		ParentIDs: map[string]bool{"parent_1": true, "parent_2": true},
		Version:   "1.0.0",
		PURLType:  purl.TypePyPi,
		Location:  extractor.LocationFromPath("/file1"),
		Plugins:   []string{"extractor_name"},
	}
}

func exampleTransitiveDependencyPackageProto() *spb.Package {
	return &spb.Package{
		Name:      "transitive_package",
		Version:   "1.0.0",
		Ecosystem: "PyPI",
		Location:  pkgLocProtoFromPath("/file1"),
		Plugins:   []string{"extractor_name"},
		ParentIds: []string{"parent_1", "parent_2"},
		Purl: &spb.Purl{
			Purl:    "pkg:pypi/transitive-package@1.0.0",
			Type:    "pypi",
			Name:    "transitive-package",
			Version: "1.0.0",
		},
	}
}

func TestPackageToProto(t *testing.T) {
	testCases := []struct {
		desc    string
		pkg     *extractor.Package
		want    *spb.Package
		wantErr error
	}{
		{
			desc: "nil",
			pkg:  nil,
			want: nil,
		},
		{
			desc: "success",
			pkg:  PurlDPKGAnnotationPackage(),
			want: PurlDPKGAnnotationPackageProto(t),
		},
		{
			desc: "transitive_dependency",
			pkg:  exampleTransitiveDependencyPackage(),
			want: exampleTransitiveDependencyPackageProto(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := proto.PackageToProto(tc.pkg)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("PackageToProto(%v) returned error %v, want error %v", tc.pkg, err, tc.wantErr)
			}

			if got != nil {
				if got.GetId() == "" {
					t.Errorf("PackageToProto(%v) returned empty ID, want non-empty ID", tc.pkg)
				}
				// Ignore the ID field because it is randomly generated.
				got.Id = ""
			}

			opts := append([]cmp.Option{protocmp.Transform()}, pkgOpts...)

			if diff := cmp.Diff(tc.want, got, opts...); diff != "" {
				t.Fatalf("PackageToProto(%v) returned diff (-want +got):\n%s", tc.pkg, diff)
			}

			// No need to test the reverse conversion if the result is nil.
			if got == nil {
				return
			}

			// Test the reverse conversion for completeness.
			gotPB, err := proto.PackageToStruct(got)
			if err != nil {
				t.Fatalf("PackageToStruct(%v) returned error %v, want nil", got, err)
			}
			if diff := cmp.Diff(tc.pkg, gotPB, opts...); diff != "" {
				t.Fatalf("PackageToStruct(%v) returned diff (-want +got):\n%s", got, diff)
			}
		})
	}
}

func TestPackageToStruct(t *testing.T) {
	testCases := []struct {
		desc    string
		pkg     *spb.Package
		want    *extractor.Package
		wantErr error
	}{
		{
			desc: "nil",
			pkg:  nil,
			want: nil,
		},
		{
			desc: "success",
			pkg:  PurlDPKGAnnotationPackageProto(t),
			want: PurlDPKGAnnotationPackage(),
		},
		{
			desc: "transitive_dependency",
			pkg:  exampleTransitiveDependencyPackageProto(),
			want: exampleTransitiveDependencyPackage(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := proto.PackageToStruct(tc.pkg)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("PackageToStruct(%v) returned error %v, want error %v", tc.pkg, err, tc.wantErr)
			}

			opts := append([]cmp.Option{protocmp.Transform()}, pkgOpts...)
			if diff := cmp.Diff(tc.want, got, opts...); diff != "" {
				t.Fatalf("PackageToStruct(%v) returned diff (-want +got):\n%s", tc.pkg, diff)
			}

			// No need to test the reverse conversion if the result is nil.
			if got == nil {
				return
			}

			// Test the reverse conversion for completeness.
			gotPB, err := proto.PackageToProto(got)
			if err != nil {
				t.Fatalf("PackageToProto(%v) returned error %v, want nil", got, err)
			}
			// Ignore the ID field because it is randomly generated.
			gotPB.Id = ""
			if diff := cmp.Diff(tc.pkg, gotPB, opts...); diff != "" {
				t.Fatalf("PackageToProto(%v) returned diff (-want +got):\n%s", got, diff)
			}
		})
	}
}
