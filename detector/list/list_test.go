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

package list_test

import (
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	dl "github.com/google/osv-scalibr/detector/list"
)

var (
	reValidName = regexp.MustCompile(`^[a-z0-9/-]+$`)
)

func TestPluginNamesValid(t *testing.T) {
	for _, initers := range dl.All {
		for _, initer := range initers {
			p, err := initer(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("initer(): %v", err)
			}
			if !reValidName.MatchString(p.Name()) {
				t.Errorf("Invalid plugin name %q", p.Name())
			}
		}
	}
}

func TestDetectorsFromName(t *testing.T) {
	testCases := []struct {
		desc     string
		name     string
		wantDets []string
		wantErr  error
	}{
		{
			desc: "Find_all_detectors_of_a_type",
			name: "cis",
			wantDets: []string{
				"cis/generic-linux/etcpasswdpermissions",
			},
		},
		{
			desc: "Find_misc_detectors",
			name: "misc",
			wantDets: []string{
				"cronjobprivesc",
				"dockersocket",
			},
		},
		{
			desc: "Find_weak_credentials_detectors",
			name: "weakcredentials",
			wantDets: []string{
				"weakcredentials/codeserver",
				"weakcredentials/etcshadow",
				"weakcredentials/filebrowser",
				"weakcredentials/winlocal",
			},
		},
		{
			desc:     "Nonexistent plugin",
			name:     "nonexistent",
			wantErr:  cmpopts.AnyError,
			wantDets: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := dl.DetectorsFromName(tc.name, &cpb.PluginConfig{})
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("dl.DetectorsFromName(%v) error got diff (-want +got):\n%s", tc.name, diff)
			}
			gotNames := []string{}
			for _, d := range got {
				gotNames = append(gotNames, d.Name())
			}
			if diff := cmp.Diff(tc.wantDets, gotNames, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
				t.Errorf("dl.DetectorsFromName(%v): got diff (-want +got):\n%s", tc.name, diff)
			}
		})
	}
}
