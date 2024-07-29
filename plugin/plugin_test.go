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

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/plugin"
)

type fakePlugin struct {
	reqs *plugin.Requirements
}

func (fakePlugin) Name() string                         { return "fake-plugin" }
func (fakePlugin) Version() int                         { return 0 }
func (p fakePlugin) Requirements() *plugin.Requirements { return p.reqs }

func TestValidateRequirements(t *testing.T) {
	testCases := []struct {
		desc       string
		pluginReqs *plugin.Requirements
		capabs     *plugin.Requirements
		wantErr    error
	}{
		{
			desc:       "No requirements",
			pluginReqs: &plugin.Requirements{},
			capabs:     &plugin.Requirements{},
			wantErr:    nil,
		},
		{
			desc:       "All requirements satisfied",
			pluginReqs: &plugin.Requirements{Network: true, RealFS: true},
			capabs:     &plugin.Requirements{Network: true, RealFS: true},
			wantErr:    nil,
		},
		{
			desc:       "One requirement not satisfied",
			pluginReqs: &plugin.Requirements{Network: true, RealFS: true},
			capabs:     &plugin.Requirements{Network: true, RealFS: false},
			wantErr:    cmpopts.AnyError,
		},
		{
			desc:       "No requirement satisfied",
			pluginReqs: &plugin.Requirements{Network: true, RealFS: true},
			capabs:     &plugin.Requirements{Network: false, RealFS: false},
			wantErr:    cmpopts.AnyError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			p := fakePlugin{reqs: tc.pluginReqs}
			err := plugin.ValidateRequirements(p, tc.capabs)
			if !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("plugin.ValidateRequirements(%v, %v) got error: %v, want: %v\n", tc.pluginReqs, tc.capabs, err, tc.wantErr)
			}
		})
	}
}

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
