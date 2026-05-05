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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/binary/proto"
	"github.com/google/osv-scalibr/inventory/location"
	"google.golang.org/protobuf/testing/protocmp"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func TestLocationToProto(t *testing.T) {
	testCases := []struct {
		desc string
		loc  *location.Location
		want *spb.Location
	}{
		{
			desc: "nil",
			loc:  nil,
			want: nil,
		},
		{
			desc: "nil_file",
			loc:  &location.Location{},
			want: &spb.Location{},
		},
		{
			desc: "file",
			loc:  &location.Location{File: &location.File{Path: "/path"}},
			want: &spb.Location{File: &spb.File{Path: "/path"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := proto.LocationToProto(tc.loc)

			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Fatalf("LocationToProto(%v) returned diff (-want +got):\n%s", tc.loc, diff)
			}

			// No need to test the reverse conversion if the result is nil.
			if got == nil {
				return
			}

			// Test the reverse conversion for completeness.
			gotPB := proto.LocationToStruct(got)
			if diff := cmp.Diff(tc.loc, gotPB, protocmp.Transform()); diff != "" {
				t.Fatalf("LocationToStruct(%v) returned diff (-want +got):\n%s", got, diff)
			}
		})
	}
}

func TestLocationToStruct(t *testing.T) {
	testCases := []struct {
		desc    string
		loc     *spb.Location
		want    *location.Location
		wantErr error
	}{
		{
			desc: "nil",
			loc:  nil,
			want: nil,
		},
		{
			desc: "nil_file",
			loc:  &spb.Location{},
			want: &location.Location{},
		},
		{
			desc: "file",
			loc:  &spb.Location{File: &spb.File{Path: "/path"}},
			want: &location.Location{File: &location.File{Path: "/path"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := proto.LocationToStruct(tc.loc)
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Fatalf("LocationToStruct(%v) returned diff (-want +got):\n%s", tc.loc, diff)
			}

			// No need to test the reverse conversion if the result is nil.
			if got == nil {
				return
			}

			// Test the reverse conversion for completeness.
			gotPB := proto.LocationToProto(got)
			if diff := cmp.Diff(tc.loc, gotPB, protocmp.Transform()); diff != "" {
				t.Fatalf("LocationToProto(%v) returned diff (-want +got):\n%s", got, diff)
			}
		})
	}
}

func pkgLocProtoFromPath(path string) *spb.PackageLocation {
	return &spb.PackageLocation{
		Desc: &spb.Location{
			File: &spb.File{Path: path},
		},
	}
}
