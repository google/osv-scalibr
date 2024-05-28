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
	"github.com/google/osv-scalibr/extractor/list"
)

func TestExtractorsFromNames(t *testing.T) {
	testCases := []struct {
		desc     string
		names    []string
		wantExts []string
		wantErr  error
	}{
		{
			desc:     "Find all extractors of a type",
			names:    []string{"python"},
			wantExts: []string{"python/wheelegg", "python/requirements"},
		},
		{
			desc:     "Case-insensitive",
			names:    []string{"Python"},
			wantExts: []string{"python/wheelegg", "python/requirements"},
		},
		{
			desc:     "Remove duplicates",
			names:    []string{"python", "python"},
			wantExts: []string{"python/wheelegg", "python/requirements"},
		},
		{
			desc:     "Nonexistent plugin",
			names:    []string{"nonexistent"},
			wantErr:  cmpopts.AnyError,
			wantExts: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := list.ExtractorsFromNames(tc.names)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("ExtractorsFromNames(%v) error got diff (-want +got):\n%s", tc.names, diff)
			}
			gotNames := []string{}
			for _, e := range got {
				gotNames = append(gotNames, e.Name())
			}
			sort := func(e1, e2 string) bool { return e1 < e2 }
			if diff := cmp.Diff(tc.wantExts, gotNames, cmpopts.SortSlices(sort)); diff != "" {
				t.Errorf("ExtractorsFromNames(%v): got diff (-want +got):\n%s", tc.names, diff)
			}
		})
	}
}

func TestExtractorFromName(t *testing.T) {
	testCases := []struct {
		desc    string
		name    string
		wantExt string
		wantErr error
	}{
		{
			desc:    "Exact name",
			name:    "python/wheelegg",
			wantExt: "python/wheelegg",
		},
		{
			desc:    "Nonexistent plugin",
			name:    "nonexistent",
			wantErr: cmpopts.AnyError,
		},
		{
			desc:    "Not an exact name",
			name:    "python",
			wantErr: cmpopts.AnyError,
		},
		{
			desc:    "Works for upper case names",
			name:    "python/Pipfile",
			wantExt: "python/Pipfile",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := list.ExtractorFromName(tc.name)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("ExtractorFromName(%v) error got diff (-want +got):\n%s", tc.name, diff)
			}
			if err != nil {
				return
			}
			if tc.wantExt != got.Name() {
				t.Errorf("ExtractorFromName(%s) = %s, want %s", tc.name, got.Name(), tc.wantExt)
			}
		})
	}
}
