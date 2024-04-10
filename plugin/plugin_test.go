// Copyright 2024 Google LLC
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

package plugin_test

import (
	"testing"

	"github.com/google/osv-scalibr/plugin"
)

func TestString(t *testing.T) {
	testCases := []struct {
		desc string
		s    *plugin.ScanStatus
		want string
	}{
		{
			desc: "Successful scan",
			s:    &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
			want: "SUCCEEDED",
		},
		{
			desc: "Partially successful scan",
			s:    &plugin.ScanStatus{Status: plugin.ScanStatusPartiallySucceeded},
			want: "PARTIALLY_SUCCEEDED",
		},
		{
			desc: "Failed scan",
			s:    &plugin.ScanStatus{Status: plugin.ScanStatusFailed, FailureReason: "failure"},
			want: "FAILED: failure",
		},
		{
			desc: "Unspecified status",
			s:    &plugin.ScanStatus{},
			want: "UNSPECIFIED",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := tc.s.String()
			if got != tc.want {
				t.Errorf("%v.String(): Got %s, want %s", tc.s, got, tc.want)
			}
		})
	}
}
