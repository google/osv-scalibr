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

package enricherlist_test

import (
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/enricher/baseimage"
	el "github.com/google/osv-scalibr/enricher/enricherlist"
)

var (
	reValidName = regexp.MustCompile(`^[a-z0-9/-]+$`)
)

func TestPluginNamesValid(t *testing.T) {
	for _, initers := range el.All {
		for _, initer := range initers {
			name := initer(&cpb.PluginConfig{}).Name()
			if !reValidName.MatchString(name) {
				t.Errorf("Invalid plugin name %q", name)
			}
		}
	}
}

func TestEnrichersFromName(t *testing.T) {
	testCases := []struct {
		desc    string
		name    string
		want    []string
		wantErr error
	}{
		{
			desc: "Find_all_extractors_of_a_type",
			name: "layerdetails",
			want: []string{baseimage.Name},
		},
		{
			desc:    "Nonexistent plugin",
			name:    "nonexistent",
			wantErr: cmpopts.AnyError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := el.EnrichersFromName(tc.name, &cpb.PluginConfig{})
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("el.EnrichersFromName(%v) error got diff (-want +got):\n%s", tc.name, diff)
			}
			var gotNames []string
			for _, e := range got {
				gotNames = append(gotNames, e.Name())
			}
			sort := func(e1, e2 string) bool { return e1 < e2 }
			if diff := cmp.Diff(tc.want, gotNames, cmpopts.SortSlices(sort)); diff != "" {
				t.Errorf("el.EnrichersFromName(%v): got diff (-want +got):\n%s", tc.name, diff)
			}
		})
	}
}
