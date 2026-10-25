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
	"github.com/google/osv-scalibr/extractor/filesystem/os/freebsd/metadata"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func TestToProto(t *testing.T) {
	testCases := []struct {
		desc string
		m    *metadata.Metadata
		want *pb.FreeBSDPackageMetadata
	}{
		{
			desc: "simple_metadata",
			m: &metadata.Metadata{
				PackageName: "curl",
			},
			want: &pb.FreeBSDPackageMetadata{
				PackageName: "curl",
			},
		},
		{
			desc: "all_fields",
			m: &metadata.Metadata{
				PackageName:    "curl",
				PackageVersion: "8.4.0",
				Origin:         "ftp/curl",
				Arch:           "freebsd:14:x86:64",
				OSID:           "freebsd",
				OSVersionID:    "14.0",
			},
			want: &pb.FreeBSDPackageMetadata{
				PackageName:    "curl",
				PackageVersion: "8.4.0",
				Origin:         "ftp/curl",
				Arch:           "freebsd:14:x86:64",
				OsId:           "freebsd",
				OsVersionId:    "14.0",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := metadata.ToProto(tc.m)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.want, got, opts...); diff != "" {
				t.Errorf("ToProto(%+v): (-want +got):\n%s", tc.m, diff)
			}
		})
	}
}

func TestToStruct(t *testing.T) {
	testCases := []struct {
		desc string
		m    *pb.FreeBSDPackageMetadata
		want *metadata.Metadata
	}{
		{
			desc: "some_fields",
			m: &pb.FreeBSDPackageMetadata{
				PackageName: "curl",
			},
			want: &metadata.Metadata{
				PackageName: "curl",
			},
		},
		{
			desc: "all_fields",
			m: &pb.FreeBSDPackageMetadata{
				PackageName:    "curl",
				PackageVersion: "8.4.0",
				Origin:         "ftp/curl",
				Arch:           "freebsd:14:x86:64",
				OsId:           "freebsd",
				OsVersionId:    "14.0",
			},
			want: &metadata.Metadata{
				PackageName:    "curl",
				PackageVersion: "8.4.0",
				Origin:         "ftp/curl",
				Arch:           "freebsd:14:x86:64",
				OSID:           "freebsd",
				OSVersionID:    "14.0",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := metadata.ToStruct(tc.m)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", tc.m, diff)
			}
		})
	}
}
