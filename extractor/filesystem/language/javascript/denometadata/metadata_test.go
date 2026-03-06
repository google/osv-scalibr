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

package denometadata_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/denometadata"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func TestToProto(t *testing.T) {
	testCases := []struct {
		desc string
		m    *denometadata.DenoMetadata
		want *pb.JavascriptDenoMetadata
	}{
		{
			desc: "set FromDenolandCdn",
			m: &denometadata.DenoMetadata{
				FromDenolandCDN: true,
			},
			want: &pb.JavascriptDenoMetadata{
				Cdn: &pb.JavascriptDenoMetadata_FromDenolandCdn{
					FromDenolandCdn: true,
				},
			},
		},
		{
			desc: "set FromUnpkgCdn",
			m: &denometadata.DenoMetadata{
				FromUnpkgCDN: true,
			},
			want: &pb.JavascriptDenoMetadata{
				Cdn: &pb.JavascriptDenoMetadata_FromUnpkgCdn{
					FromUnpkgCdn: true,
				},
			},
		},
		{
			desc: "set FromESMCdn",
			m: &denometadata.DenoMetadata{
				FromESMCDN: true,
			},
			want: &pb.JavascriptDenoMetadata{
				Cdn: &pb.JavascriptDenoMetadata_FromEsmCdn{
					FromEsmCdn: true,
				},
			},
		},
		{
			desc: "set repository URL",
			m: &denometadata.DenoMetadata{
				URL: "https://www.example.com",
			},
			want: &pb.JavascriptDenoMetadata{
				Url: "https://www.example.com",
			},
		},
		{
			desc: "multiple CDNs",
			m: &denometadata.DenoMetadata{
				FromDenolandCDN: true,
				FromUnpkgCDN:    false,
				FromESMCDN:      false,
				URL:             "https://www.example.com",
			},
			want: &pb.JavascriptDenoMetadata{
				Url: "https://www.example.com",
				Cdn: &pb.JavascriptDenoMetadata_FromDenolandCdn{
					FromDenolandCdn: true,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := denometadata.ToProto(tc.m)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.want, got, opts...); diff != "" {
				t.Errorf("denometadata.ToProto(%+v): (-want +got):\n%s", tc.m, diff)
			}

			// Test the reverse conversion for completeness.
			// Skip the reverse comparison for the "multiple repositories" test case
			// since we expect only one repository to be set after the round trip
			if tc.desc == "multiple repositories" {
				return
			}

			gotStruct := denometadata.ToStruct(got)
			if diff := cmp.Diff(tc.m, gotStruct); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", got, diff)
			}
		})
	}
}

func TestToStruct(t *testing.T) {
	testCases := []struct {
		desc string
		m    *pb.JavascriptDenoMetadata
		want *denometadata.DenoMetadata
	}{

		{
			desc: "from npm",
			m:    &pb.JavascriptDenoMetadata{},
			want: &denometadata.DenoMetadata{},
		},
		{
			desc: "from jsr",
			m:    &pb.JavascriptDenoMetadata{},
			want: &denometadata.DenoMetadata{},
		},
		{
			desc: "from denoland",
			m: &pb.JavascriptDenoMetadata{
				Cdn: &pb.JavascriptDenoMetadata_FromDenolandCdn{
					FromDenolandCdn: true,
				},
			},
			want: &denometadata.DenoMetadata{
				FromDenolandCDN: true,
			},
		},
		{
			desc: "from unpkg",
			m: &pb.JavascriptDenoMetadata{
				Cdn: &pb.JavascriptDenoMetadata_FromUnpkgCdn{
					FromUnpkgCdn: true,
				},
			},
			want: &denometadata.DenoMetadata{
				FromUnpkgCDN: true,
			},
		},
		{
			desc: "from esm",
			m: &pb.JavascriptDenoMetadata{
				Cdn: &pb.JavascriptDenoMetadata_FromEsmCdn{
					FromEsmCdn: true,
				},
			},
			want: &denometadata.DenoMetadata{
				FromESMCDN: true,
			},
		},
		{
			desc: "with repository URL",
			m: &pb.JavascriptDenoMetadata{
				Url: "https://www.example.com",
			},
			want: &denometadata.DenoMetadata{
				URL: "https://www.example.com",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := denometadata.ToStruct(tc.m)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", tc.m, diff)
			}

			// Test the reverse conversion for completeness.
			gotProto := denometadata.ToProto(got)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.m, gotProto, opts...); diff != "" {
				t.Errorf("denometadata.ToProto(%+v): (-want +got):\n%s", got, diff)
			}
		})
	}
}
