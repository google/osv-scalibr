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
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx/metadata"
	"github.com/google/osv-scalibr/purl"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

var (
	purlStructDeb1 = &purl.PackageURL{
		Type:      purl.TypeDebian,
		Namespace: "debian",
		Name:      "some-package",
		Version:   "1.0.0",
		Qualifiers: purl.QualifiersFromMap(map[string]string{
			"arch":   "amd64",
			"distro": "buster",
		}),
		Subpath: "some/subpath",
	}

	purlProtoDeb1 = &pb.Purl{
		Purl:      "pkg:deb/debian/some-package@1.0.0?arch=amd64&distro=buster#some/subpath",
		Type:      purl.TypeDebian,
		Namespace: "debian",
		Name:      "some-package",
		Version:   "1.0.0",
		Qualifiers: []*pb.Qualifier{
			&pb.Qualifier{
				Key:   "arch",
				Value: "amd64",
			},
			&pb.Qualifier{
				Key:   "distro",
				Value: "buster",
			},
		},
		Subpath: "some/subpath",
	}
)

func TestToProto(t *testing.T) {
	testCases := []struct {
		desc string
		m    *metadata.Metadata
		want *pb.SPDXPackageMetadata
	}{{
		desc: "set metadata",
		m: &metadata.Metadata{
			PURL: purlStructDeb1,
		},
		want: &pb.SPDXPackageMetadata{
			Purl: purlProtoDeb1,
		},
	}, {
		desc: "set all fields",
		m: &metadata.Metadata{
			PURL: purlStructDeb1,
			CPEs: []string{"cpe:2.3:a:some-package:1.0.0:*:*:*:*:*:*:*"},
		},
		want: &pb.SPDXPackageMetadata{
			Purl: purlProtoDeb1,
			Cpes: []string{"cpe:2.3:a:some-package:1.0.0:*:*:*:*:*:*:*"},
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := metadata.ToProto(tc.m)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.want, got, opts...); diff != "" {
				t.Errorf("Metadata.ToProto(%+v) returned diff (-want +got):\n%s", tc.m, diff)
			}

			// Test the reverse conversion for completeness.
			gotStruct := metadata.ToStruct(got)
			if diff := cmp.Diff(tc.m, gotStruct); diff != "" {
				t.Errorf("ToStruct(%+v) returned diff (-want +got):\n%s", got, diff)
			}
		})
	}
}

func TestToStruct(t *testing.T) {
	testCases := []struct {
		name string
		m    *pb.SPDXPackageMetadata
		want *metadata.Metadata
	}{
		{
			name: "some fields",
			m: &pb.SPDXPackageMetadata{
				Purl: purlProtoDeb1,
			},
			want: &metadata.Metadata{
				PURL: purlStructDeb1,
			},
		},
		{
			name: "all fields",
			m: &pb.SPDXPackageMetadata{
				Purl: purlProtoDeb1,
				Cpes: []string{"cpe:2.3:a:some-package:1.0.0:*:*:*:*:*:*:*"},
			},
			want: &metadata.Metadata{
				PURL: purlStructDeb1,
				CPEs: []string{"cpe:2.3:a:some-package:1.0.0:*:*:*:*:*:*:*"},
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
			gotProto := metadata.ToProto(got)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.m, gotProto, opts...); diff != "" {
				t.Errorf("Metadata.ToProto(%+v): (-want +got):\n%s", got, diff)
			}
		})
	}
}
