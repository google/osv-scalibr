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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/plugin"
	pl "github.com/google/osv-scalibr/plugin/list"
)

func TestPluginNamesUnique(t *testing.T) {
	names := make(map[string]plugin.Plugin)
	for _, p := range pl.All() {
		if prev, ok := names[p.Name()]; ok {
			t.Errorf("%q for plugin %v already used by plugin: %v", p.Name(), p, prev)
		} else {
			names[p.Name()] = p
		}
	}
}

func TestFromCapabilities(t *testing.T) {
	capab := &plugin.Capabilities{OS: plugin.OSLinux}
	want := []string{"os/snap", "weakcredentials/etcshadow"} // Available for Linux
	dontWant := []string{"os/homebrew", "windows/dismpatch"} // Not available for Linux
	plugins := pl.FromCapabilities(capab)

	for _, w := range want {
		found := false
		for _, p := range plugins {
			if p.Name() == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("pl.FromCapabilities(%v): %q not included in results, should be", capab, w)
		}
	}
	for _, dw := range dontWant {
		for _, p := range plugins {
			if p.Name() == dw {
				t.Errorf("pl.FromCapabilities(%v): %q included in results, shouldn't be", capab, dontWant)
			}
		}
	}
}

func TestFromNames(t *testing.T) {
	testCases := []struct {
		desc      string
		names     []string
		wantNames []string
		wantErr   error
	}{
		{
			desc:      "Find_all_Plugins_of_a_type",
			names:     []string{"python", "windows", "cis", "vex", "layerdetails"},
			wantNames: []string{"python/pdmlock", "python/pipfilelock", "python/poetrylock", "python/condameta", "python/uvlock", "python/wheelegg", "python/requirements", "python/requirementsnet", "python/setup", "windows/dismpatch", "cis/generic-linux/etcpasswdpermissions", "vex/cachedir", "vex/filter", "vex/os-duplicate/dpkg", "vex/os-duplicate/rpm", "enricher/baseimage"},
		},
		{
			desc:      "Remove_duplicates",
			names:     []string{"python", "python"},
			wantNames: []string{"python/pdmlock", "python/pipfilelock", "python/poetrylock", "python/condameta", "python/uvlock", "python/wheelegg", "python/requirements", "python/requirementsnet", "python/setup"},
		},
		{
			desc:      "Nonexistent_plugin",
			names:     []string{"nonexistent"},
			wantErr:   cmpopts.AnyError,
			wantNames: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := pl.FromNames(tc.names)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("pl.FromNames(%v) error got diff (-want +got):\n%s", tc.names, diff)
			}
			gotNames := []string{}
			for _, p := range got {
				gotNames = append(gotNames, p.Name())
			}
			sort := func(p1, p2 string) bool { return p1 < p2 }
			if diff := cmp.Diff(tc.wantNames, gotNames, cmpopts.SortSlices(sort)); diff != "" {
				t.Errorf("pl.FromNames(%v): got diff (-want +got):\n%s", tc.names, diff)
			}
		})
	}
}

func TestFromName(t *testing.T) {
	testCases := []struct {
		desc     string
		name     string
		wantName string
		wantErr  error
	}{
		{
			desc:     "Exact_name",
			name:     "govulncheck/binary",
			wantName: "govulncheck/binary",
		},
		{
			desc:    "Nonexistent_plugin",
			name:    "nonexistent",
			wantErr: cmpopts.AnyError,
		},
		{
			desc:    "Not_an_exact_name",
			name:    "python",
			wantErr: cmpopts.AnyError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := pl.FromName(tc.name)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("pl.FromName(%v) error got diff (-want +got):\n%s", tc.name, diff)
			}
			if err != nil {
				return
			}
			if tc.wantName != got.Name() {
				t.Errorf("pl.FromName(%s): want %s, got %s", tc.name, tc.wantName, got.Name())
			}
		})
	}
}
