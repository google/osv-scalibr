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

package proto_test

import (
	"testing"

	"github.com/google/osv-scalibr/binary/proto"
	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/google/osv-scalibr/extractor"
)

// --- Struct to Proto

func TestAnnotationToProto(t *testing.T) {
	testCases := []struct {
		desc string
		a    extractor.Annotation
		want spb.Package_AnnotationEnum
	}{
		{
			desc: "zero_value",
		},
		{
			desc: "unspecified",
			a:    extractor.Unknown,
			want: spb.Package_UNSPECIFIED,
		},
		{
			desc: "transitional",
			a:    extractor.Transitional,
			want: spb.Package_TRANSITIONAL,
		},
		{
			desc: "inside_os_package",
			a:    extractor.InsideOSPackage,
			want: spb.Package_INSIDE_OS_PACKAGE,
		},
		{
			desc: "inside_cache_dir",
			a:    extractor.InsideCacheDir,
			want: spb.Package_INSIDE_CACHE_DIR,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := proto.AnnotationToProto(tc.a)
			if got != tc.want {
				t.Errorf("AnnotationToProto(%v) = %v, want %v", tc.a, got, tc.want)
			}
		})
	}
}

// --- Proto to Struct

func TestAnnotationToStruct(t *testing.T) {
	testCases := []struct {
		desc string
		a    spb.Package_AnnotationEnum
		want extractor.Annotation
	}{
		{
			desc: "zero_value",
		},
		{
			desc: "unspecified",
			a:    spb.Package_UNSPECIFIED,
			want: extractor.Unknown,
		},
		{
			desc: "transitional",
			a:    spb.Package_TRANSITIONAL,
			want: extractor.Transitional,
		},
		{
			desc: "inside_os_package",
			a:    spb.Package_INSIDE_OS_PACKAGE,
			want: extractor.InsideOSPackage,
		},
		{
			desc: "inside_cache_dir",
			a:    spb.Package_INSIDE_CACHE_DIR,
			want: extractor.InsideCacheDir,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := proto.AnnotationToStruct(tc.a)
			if got != tc.want {
				t.Errorf("AnnotationToStruct(%v) = %v, want %v", tc.a, got, tc.want)
			}
		})
	}
}
