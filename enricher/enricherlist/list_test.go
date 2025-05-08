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
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/baseimage"
	el "github.com/google/osv-scalibr/enricher/enricherlist"
	"github.com/google/osv-scalibr/plugin"
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

func TestFromName(t *testing.T) {
	testCases := []struct {
		desc    string
		name    string
		want    string
		wantErr error
	}{
		{
			desc: "Exact name",
			name: baseimage.Name,
			want: baseimage.Name,
		},
		{
			desc:    "Nonexistent plugin",
			name:    "nonexistent",
			wantErr: cmpopts.AnyError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := el.FromName(tc.name)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("el.FromName(%v) error got diff (-want +got):\n%s", tc.name, diff)
			}
			if err != nil {
				return
			}
			if tc.want != got.Name() {
				t.Errorf("el.FromName(%s): want %s, got %s", tc.name, tc.want, got.Name())
			}
		})
	}
}

func TestFromNames(t *testing.T) {
	testCases := []struct {
		desc    string
		names   []string
		want    []string
		wantErr error
	}{
		{
			desc:  "Find all extractors of a type",
			names: []string{"layerdetails"},
			want:  []string{baseimage.Name},
		},
		{
			desc:  "Remove duplicates",
			names: []string{"layerdetails", "layerdetails"},
			want:  []string{baseimage.Name},
		},
		{
			desc:    "Nonexistent plugin",
			names:   []string{"nonexistent"},
			wantErr: cmpopts.AnyError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := el.FromNames(tc.names)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("el.ExtractorsFromNames(%v) error got diff (-want +got):\n%s", tc.names, diff)
			}
			var gotNames []string
			for _, e := range got {
				gotNames = append(gotNames, e.Name())
			}
			sort := func(e1, e2 string) bool { return e1 < e2 }
			if diff := cmp.Diff(tc.want, gotNames, cmpopts.SortSlices(sort)); diff != "" {
				t.Errorf("el.ExtractorsFromNames(%v): got diff (-want +got):\n%s", tc.names, diff)
			}
		})
	}
}

func TestFilterByCapabilities(t *testing.T) {
	tests := []struct {
		desc              string
		enrichers         []enricher.Enricher
		capabilities      *plugin.Capabilities
		wantEnricherNames []string
	}{
		{
			desc: "No capabilities",
			enrichers: []enricher.Enricher{
				&baseimage.Enricher{},
			},
		},
		{
			desc:         "Network online",
			capabilities: &plugin.Capabilities{Network: plugin.NetworkOnline},
			enrichers: []enricher.Enricher{
				&baseimage.Enricher{},
			},
			wantEnricherNames: []string{baseimage.Name},
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := el.FilterByCapabilities(tc.enrichers, tc.capabilities)
			var gotNames []string
			for _, e := range got {
				gotNames = append(gotNames, e.Name())
			}
			sort := func(e1, e2 string) bool { return e1 < e2 }
			if diff := cmp.Diff(tc.wantEnricherNames, gotNames, cmpopts.SortSlices(sort)); diff != "" {
				t.Errorf("el.FilterByCapabilities(%v, %v): got diff (-want +got):\n%s", tc.enrichers, tc.capabilities, diff)
			}
		})
	}
}

func TestFromCapabilities(t *testing.T) {
	tests := []struct {
		desc         string
		capabilities *plugin.Capabilities
		wantInclude  []string
		wantExclude  []string
	}{
		{
			desc:        "No capabilities",
			wantExclude: []string{baseimage.Name},
		},
		{
			desc:         "Network online",
			capabilities: &plugin.Capabilities{Network: plugin.NetworkOnline},
			wantInclude:  []string{baseimage.Name},
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := el.FromCapabilities(tc.capabilities)
			var gotNames []string
			for _, e := range got {
				gotNames = append(gotNames, e.Name())
			}
			for _, e := range tc.wantInclude {
				if !slices.Contains(gotNames, e) {
					t.Errorf("el.FromCapabilities(%v): got %s, but should include %s", tc.capabilities, gotNames, e)
				}
			}
			for _, e := range tc.wantExclude {
				if slices.Contains(gotNames, e) {
					t.Errorf("el.FromCapabilities(%v): got %s, but should exclude %s", tc.capabilities, gotNames, e)
				}
			}
		})
	}
}
