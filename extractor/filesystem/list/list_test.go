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
	el "github.com/google/osv-scalibr/extractor/filesystem/list"
)

var (
	reValidName = regexp.MustCompile(`^[a-z0-9/-]+$`)
)

func TestPluginNamesValid(t *testing.T) {
	for _, initers := range el.All {
		for _, initer := range initers {
			name := initer().Name()
			if !reValidName.MatchString(name) {
				t.Errorf("Invalid plugin name %q", name)
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
			desc:     "Find all extractors of a type",
			name:     "python",
			wantExts: []string{"python/pdmlock", "python/pipfilelock", "python/poetrylock", "python/pylock", "python/condameta", "python/uvlock", "python/wheelegg", "python/requirements", "python/setup"},
		},
		{
			desc:     "Nonexistent plugin",
			name:     "nonexistent",
			wantErr:  cmpopts.AnyError,
			wantExts: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := el.ExtractorsFromName(tc.name)
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
