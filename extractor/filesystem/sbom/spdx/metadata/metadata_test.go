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
	"google.golang.org/protobuf/proto"
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
			PURL: purlStructDeb1,
		},
		p:    nil,
		want: nil,
	}, {
		desc: "set metadata",
		m: &metadata.Metadata{
			PURL: purlStructDeb1,
		},
		p: &pb.Package{Name: "some-package"},
		want: &pb.Package{
			Name: "some-package",
			Metadata: &pb.Package_SpdxMetadata{
				SpdxMetadata: &pb.SPDXPackageMetadata{
					Purl: purlProtoDeb1,
				},
			},
		},
	}, {
		desc: "override metadata",
		m: &metadata.Metadata{
			PURL: &purl.PackageURL{
				Type:      purl.TypeAlpm,
				Namespace: "alpine",
				Name:      "other-package",
				Version:   "2.0.0",
			},
		},
		p: &pb.Package{
			Name: "some-package",
			Metadata: &pb.Package_SpdxMetadata{
				SpdxMetadata: &pb.SPDXPackageMetadata{
					Purl: purlProtoDeb1,
				},
			},
		},
		want: &pb.Package{
			Name: "some-package",
			Metadata: &pb.Package_SpdxMetadata{
				SpdxMetadata: &pb.SPDXPackageMetadata{
					Purl: &pb.Purl{
						Purl:      "pkg:alpm/alpine/other-package@2.0.0",
						Type:      purl.TypeAlpm,
						Namespace: "alpine",
						Name:      "other-package",
						Version:   "2.0.0",
					},
				},
			},
		},
	}, {
		desc: "set all fields",
		m: &metadata.Metadata{
			PURL: purlStructDeb1,
			CPEs: []string{"cpe:2.3:a:some-package:1.0.0:*:*:*:*:*:*:*"},
		},
		p: &pb.Package{Name: "some-package"},
		want: &pb.Package{
			Name: "some-package",
			Metadata: &pb.Package_SpdxMetadata{
				SpdxMetadata: &pb.SPDXPackageMetadata{
					Purl: purlProtoDeb1,
					Cpes: []string{"cpe:2.3:a:some-package:1.0.0:*:*:*:*:*:*:*"},
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
			got := metadata.ToStruct(p.GetSpdxMetadata())
			if diff := cmp.Diff(tc.m, got); diff != "" {
				t.Errorf("ToStruct(%+v) returned diff (-want +got):\n%s", p, diff)
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
			name: "nil",
			m:    nil,
			want: nil,
		},
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
			gotP := &pb.Package{}
			wantP := &pb.Package{
				Metadata: &pb.Package_SpdxMetadata{
					SpdxMetadata: tc.m,
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
