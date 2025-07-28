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

package convert_test

import (
	"reflect"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/depsjson"
	"github.com/google/osv-scalibr/internal/proto/packagemetadata"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// TODO: b/421456154 - Remove once all metadata is migrated to the new format.
func TestSupportsStruct(t *testing.T) {
	testCases := []struct {
		desc string
		m    any
		want bool
	}{
		{
			desc: "filesystem/language/dotnet/depsjson/depsjson",
			m:    &depsjson.Metadata{},
			want: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := packagemetadata.SupportsStruct(reflect.TypeOf(tc.m))
			if got != tc.want {
				t.Errorf("SupportsStruct(%v) = %v, want: %v", tc.m, got, tc.want)
			}
		})
	}
}

// TODO: b/421456154 - Remove once all metadata is migrated to the new format.
func TestSupportsProto(t *testing.T) {
	testCases := []struct {
		desc string
		p    any
		want bool
	}{
		{
			desc: "filesystem/language/dotnet/depsjson/depsjson - package type supported",
			p:    &pb.Package_DepsjsonMetadata{},
			want: true,
		},
		{
			desc: "filesystem/language/dotnet/depsjson/depsjson - base type unsupported",
			p:    &pb.DEPSJSONMetadata{},
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := packagemetadata.SupportsProto(reflect.TypeOf(tc.p))
			if got != tc.want {
				t.Errorf("SupportsProto(%v) = %v, want: %v", tc.p, got, tc.want)
			}
		})
	}
}
