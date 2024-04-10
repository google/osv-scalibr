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

package list_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	dl "github.com/google/osv-scalibr/detector/list"
)

func TestDetectorsFromNames(t *testing.T) {
	testCases := []struct {
		desc     string
		names    []string
		wantDets []string
		wantErr  error
	}{
		{
			desc:     "Find all detectors of a type",
			names:    []string{"cis"},
			wantDets: []string{"cis/generic_linux/etcpasswdpermissions"},
		},
		{
			desc:     "Case-insensitive",
			names:    []string{"CIS"},
			wantDets: []string{"cis/generic_linux/etcpasswdpermissions"},
		},
		{
			desc:     "Remove duplicates",
			names:    []string{"cis", "cis"},
			wantDets: []string{"cis/generic_linux/etcpasswdpermissions"},
		},
		{
			desc:     "Nonexistent plugin",
			names:    []string{"nonexistent"},
			wantErr:  cmpopts.AnyError,
			wantDets: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := dl.DetectorsFromNames(tc.names)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("dl.DetectorsFromNames(%v) error got diff (-want +got):\n%s", tc.names, diff)
			}
			gotNames := []string{}
			for _, d := range got {
				gotNames = append(gotNames, d.Name())
			}
			if diff := cmp.Diff(tc.wantDets, gotNames); diff != "" {
				t.Errorf("dl.DetectorsFromNames(%v): got diff (-want +got):\n%s", tc.names, diff)
			}
		})
	}
}
