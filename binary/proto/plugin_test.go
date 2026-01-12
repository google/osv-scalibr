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

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/binary/proto"
	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/google/osv-scalibr/plugin"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestPluginStatusToProto(t *testing.T) {
	testCases := []struct {
		desc string
		s    *plugin.Status
		want *spb.PluginStatus
	}{
		{
			desc: "nil",
			s:    nil,
			want: nil,
		},
		{
			desc: "success",
			s: &plugin.Status{
				Name:    "test-plugin",
				Version: 1,
				Status: &plugin.ScanStatus{
					Status: plugin.ScanStatusSucceeded,
				},
			},
			want: &spb.PluginStatus{
				Name:    "test-plugin",
				Version: 1,
				Status: &spb.ScanStatus{
					Status: spb.ScanStatus_SUCCEEDED,
				},
			},
		},
		{
			desc: "converts_file_errors",
			s: &plugin.Status{
				Name:    "test-plugin-with-file-errors",
				Version: 1,
				Status: &plugin.ScanStatus{
					Status: plugin.ScanStatusPartiallySucceeded,
					FileErrors: []*plugin.FileError{
						{FilePath: "file1", ErrorMessage: "error1"},
						{FilePath: "file2", ErrorMessage: "error2"},
					},
				},
			},
			want: &spb.PluginStatus{
				Name:    "test-plugin-with-file-errors",
				Version: 1,
				Status: &spb.ScanStatus{
					Status: spb.ScanStatus_PARTIALLY_SUCCEEDED,
					FileErrors: []*spb.FileError{
						{FilePath: "file1", ErrorMessage: "error1"},
						{FilePath: "file2", ErrorMessage: "error2"},
					},
				},
			},
		},
		{
			desc: "nil_status",
			s: &plugin.Status{
				Name:    "test-plugin",
				Version: 1,
			},
			want: &spb.PluginStatus{
				Name:    "test-plugin",
				Version: 1,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := proto.PluginStatusToProto(tc.s)
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Fatalf("PluginStatusToProto(%v) returned diff (-want +got):\n%s", tc.s, diff)
			}

			// Test the reverse conversion for completeness.
			gotPB := proto.PluginStatusToStruct(got)
			if diff := cmp.Diff(tc.s, gotPB, protocmp.Transform()); diff != "" {
				t.Fatalf("PluginStatusToStruct(%v) returned diff (-want +got):\n%s", got, diff)
			}
		})
	}
}
