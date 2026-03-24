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

package purlproto_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/purl/purlproto"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func TestToProto(t *testing.T) {
	testCases := []struct {
		desc string
		purl *purl.PackageURL
		want *pb.Purl
	}{
		{
			desc: "nil",
			purl: nil,
			want: nil,
		},
		{
			desc: "success",
			purl: &purl.PackageURL{
				Type:       purl.TypeDebian,
				Namespace:  "debian",
				Name:       "software",
				Version:    "1.0.0",
				Qualifiers: purl.QualifiersFromMap(map[string]string{"arch": "amd64", "distro": "jammy"}),
				Subpath:    "amd64",
			},
			want: &pb.Purl{
				Purl:      "pkg:deb/debian/software@1.0.0?arch=amd64&distro=jammy#amd64",
				Type:      "deb",
				Namespace: "debian",
				Name:      "software",
				Version:   "1.0.0",
				Qualifiers: []*pb.Qualifier{
					&pb.Qualifier{Key: "arch", Value: "amd64"},
					&pb.Qualifier{Key: "distro", Value: "jammy"},
				},
				Subpath: "amd64",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := purlproto.ToProto(tc.purl)
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Fatalf("ToProto(%v) returned diff (-want +got):\n%s", tc.purl, diff)
			}
		})
	}
}

func TestFromProto(t *testing.T) {
	testCases := []struct {
		desc string
		purl *pb.Purl
		want *purl.PackageURL
	}{
		{
			desc: "nil",
			purl: nil,
			want: nil,
		},
		{
			desc: "success",
			purl: &pb.Purl{
				Purl:      "pkg:deb/debian/software@1.0.0?arch=amd64&distro=jammy#amd64",
				Type:      "deb",
				Namespace: "debian",
				Name:      "software",
				Version:   "1.0.0",
				Qualifiers: []*pb.Qualifier{
					&pb.Qualifier{Key: "arch", Value: "amd64"},
					&pb.Qualifier{Key: "distro", Value: "jammy"},
				},
				Subpath: "amd64",
			},
			want: &purl.PackageURL{
				Type:       purl.TypeDebian,
				Namespace:  "debian",
				Name:       "software",
				Version:    "1.0.0",
				Qualifiers: purl.QualifiersFromMap(map[string]string{"arch": "amd64", "distro": "jammy"}),
				Subpath:    "amd64",
			},
		},
		{
			desc: "missing PURL string",
			purl: &pb.Purl{
				Type:      "deb",
				Namespace: "debian",
				Name:      "software",
				Version:   "1.0.0",
				Qualifiers: []*pb.Qualifier{
					&pb.Qualifier{Key: "arch", Value: "amd64"},
					&pb.Qualifier{Key: "distro", Value: "jammy"},
				},
				Subpath: "amd64",
			},
			want: &purl.PackageURL{
				Type:       purl.TypeDebian,
				Namespace:  "debian",
				Name:       "software",
				Version:    "1.0.0",
				Qualifiers: purl.QualifiersFromMap(map[string]string{"arch": "amd64", "distro": "jammy"}),
				Subpath:    "amd64",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := purlproto.FromProto(tc.purl)
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Fatalf("FromProto(%v) returned diff (-want +got):\n%s", tc.purl, diff)
			}
		})
	}
}
