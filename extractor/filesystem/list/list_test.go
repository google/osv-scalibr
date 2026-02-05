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

package list_test

import (
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	el "github.com/google/osv-scalibr/extractor/filesystem/list"
)

var (
	reValidName = regexp.MustCompile(`^[a-z0-9/-]+$`)
)

func TestPluginNamesValid(t *testing.T) {
	for _, initers := range el.All {
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

func TestExtractorsFromName(t *testing.T) {
	testCases := []struct {
		desc     string
		name     string
		wantExts []string
		wantErr  error
	}{
		{
			desc:     "Find_all_extractors_of_a_type",
			name:     "python",
			wantExts: []string{"python/pdmlock", "python/pipfilelock", "python/poetrylock", "python/pylock", "python/condameta", "python/uvlock", "python/wheelegg", "python/requirements", "python/setup"},
		},
		{
			desc:     "Nonexistent_plugin",
			name:     "nonexistent",
			wantErr:  cmpopts.AnyError,
			wantExts: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := el.ExtractorsFromName(tc.name, &cpb.PluginConfig{})
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("el.ExtractorsFromName(%v) error got diff (-want +got):\n%s", tc.name, diff)
			}
			gotNames := []string{}
			for _, e := range got {
				gotNames = append(gotNames, e.Name())
			}
			sort := func(e1, e2 string) bool { return e1 < e2 }
			if diff := cmp.Diff(tc.wantExts, gotNames, cmpopts.SortSlices(sort)); diff != "" {
				t.Errorf("el.ExtractorsFromName(%v): got diff (-want +got):\n%s", tc.name, diff)
			}
		})
	}
}
