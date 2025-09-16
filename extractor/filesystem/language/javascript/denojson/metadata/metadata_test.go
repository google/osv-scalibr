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

package metadata_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/denojson/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func TestSetProto(t *testing.T) {
	testCases := []struct {
		desc string
		m    *metadata.JavascriptDenoJSONMetadata
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
			m:    &metadata.JavascriptDenoJSONMetadata{},
			p:    nil,
			want: nil,
		},
		{
			desc: "set FromDenolandCdn",
			m: &metadata.JavascriptDenoJSONMetadata{
				FromDenolandCdn: true,
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_DenoMetadata{
					DenoMetadata: &pb.JavascriptDenoJSONMetadata{
						Cdn: &pb.JavascriptDenoJSONMetadata_FromDenolandCdn{
							FromDenolandCdn: true,
						},
					},
				},
			},
		},
		{
			desc: "set FromUnpkgCdn",
			m: &metadata.JavascriptDenoJSONMetadata{
				FromUnpkgCdn: true,
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_DenoMetadata{
					DenoMetadata: &pb.JavascriptDenoJSONMetadata{
						Cdn: &pb.JavascriptDenoJSONMetadata_FromUnpkgCdn{
							FromUnpkgCdn: true,
						},
					},
				},
			},
		},
		{
			desc: "set FromESMCdn",
			m: &metadata.JavascriptDenoJSONMetadata{
				FromESMCdn: true,
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_DenoMetadata{
					DenoMetadata: &pb.JavascriptDenoJSONMetadata{
						Cdn: &pb.JavascriptDenoJSONMetadata_FromEsmCdn{
							FromEsmCdn: true,
						},
					},
				},
			},
		},
		{
			desc: "set repository URL",
			m: &metadata.JavascriptDenoJSONMetadata{
				Url: "https://www.example.com",
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_DenoMetadata{
					DenoMetadata: &pb.JavascriptDenoJSONMetadata{
						Url: "https://www.example.com",
					},
				},
			},
		},
		{
			desc: "override metadata",
			m: &metadata.JavascriptDenoJSONMetadata{
				Url: "https://jsr.io/package",
			},
			p: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_DenoMetadata{
					DenoMetadata: &pb.JavascriptDenoJSONMetadata{},
				},
			},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_DenoMetadata{
					DenoMetadata: &pb.JavascriptDenoJSONMetadata{
						Url: "https://jsr.io/package",
					},
				},
			},
		},
		{
			desc: "multiple CDNs",
			m: &metadata.JavascriptDenoJSONMetadata{
				FromDenolandCdn: true,
				FromUnpkgCdn:    false,
				FromESMCdn:      false,
				Url:             "https://www.example.com",
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_DenoMetadata{
					DenoMetadata: &pb.JavascriptDenoJSONMetadata{
						Url: "https://www.example.com",
						Cdn: &pb.JavascriptDenoJSONMetadata_FromDenolandCdn{
							FromDenolandCdn: true,
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			p := proto.Clone(tc.p).(*pb.Package)
			if tc.m != nil {
				tc.m.SetProto(p)
			}
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.want, p, opts...); diff != "" {
				t.Errorf("Metadata{%+v}.SetProto(%+v): (-want +got):\n%s", tc.m, tc.p, diff)
			}

			// Test the reverse conversion for completeness.
			if tc.p == nil && tc.want == nil {
				return
			}

			// Skip the reverse comparison for the "multiple repositories" test case
			// since we expect only one repository to be set after the round trip
			if tc.desc == "multiple repositories" {
				return
			}

			got := metadata.ToStruct(p.GetDenoMetadata())
			if diff := cmp.Diff(tc.m, got); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", p.GetDenoMetadata(), diff)
			}
		})
	}
}

func TestToStruct(t *testing.T) {
	testCases := []struct {
		desc string
		m    *pb.JavascriptDenoJSONMetadata
		want *metadata.JavascriptDenoJSONMetadata
	}{
		{
			desc: "nil",
			m:    nil,
			want: nil,
		},
		{
			desc: "from npm",
			m:    &pb.JavascriptDenoJSONMetadata{},
			want: &metadata.JavascriptDenoJSONMetadata{},
		},
		{
			desc: "from jsr",
			m:    &pb.JavascriptDenoJSONMetadata{},
			want: &metadata.JavascriptDenoJSONMetadata{},
		},
		{
			desc: "from denoland",
			m: &pb.JavascriptDenoJSONMetadata{
				Cdn: &pb.JavascriptDenoJSONMetadata_FromDenolandCdn{
					FromDenolandCdn: true,
				},
			},
			want: &metadata.JavascriptDenoJSONMetadata{
				FromDenolandCdn: true,
			},
		},
		{
			desc: "from unpkg",
			m: &pb.JavascriptDenoJSONMetadata{
				Cdn: &pb.JavascriptDenoJSONMetadata_FromUnpkgCdn{
					FromUnpkgCdn: true,
				},
			},
			want: &metadata.JavascriptDenoJSONMetadata{
				FromUnpkgCdn: true,
			},
		},
		{
			desc: "from esm",
			m: &pb.JavascriptDenoJSONMetadata{
				Cdn: &pb.JavascriptDenoJSONMetadata_FromEsmCdn{
					FromEsmCdn: true,
				},
			},
			want: &metadata.JavascriptDenoJSONMetadata{
				FromESMCdn: true,
			},
		},
		{
			desc: "with repository URL",
			m: &pb.JavascriptDenoJSONMetadata{
				Url: "https://www.example.com",
			},
			want: &metadata.JavascriptDenoJSONMetadata{
				Url: "https://www.example.com",
			},
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
				Metadata: &pb.Package_DenoMetadata{
					DenoMetadata: tc.m,
				},
			}
			got.SetProto(gotP)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(wantP, gotP, opts...); diff != "" {
				t.Errorf("Metadata{%+v}.SetProto(%+v): (-want +got):\n%s", got, wantP, diff)
			}
		})
	}
}
