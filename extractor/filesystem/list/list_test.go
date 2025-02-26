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
	"github.com/google/osv-scalibr/extractor/filesystem"
	el "github.com/google/osv-scalibr/extractor/filesystem/list"
	"github.com/google/osv-scalibr/extractor/filesystem/os/homebrew"
	"github.com/google/osv-scalibr/extractor/filesystem/os/snap"
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

func TestFromCapabilities(t *testing.T) {
	found := false
	capab := &plugin.Capabilities{OS: plugin.OSLinux}
	want := "os/snap"         // For Linux
	dontWant := "os/homebrew" // For Mac
	for _, ex := range el.FromCapabilities(capab) {
		if ex.Name() == want {
			found = true
			break
		}
		if ex.Name() == dontWant {
			t.Errorf("el.FromCapabilities(%v): %q included in results, shouldn't be", capab, dontWant)
		}
	}
	if !found {
		t.Errorf("el.FromCapabilities(%v): %q not included in results, should be", capab, want)
	}
}

func TestFilterByCapabilities(t *testing.T) {
	capab := &plugin.Capabilities{OS: plugin.OSLinux}
	exs := []filesystem.Extractor{snap.NewDefault(), homebrew.New()}
	got := el.FilterByCapabilities(exs, capab)
	if len(got) != 1 {
		t.Fatalf("el.FilterCapabilities(%v, %v): want 1 plugin, got %d", exs, capab, len(got))
	}
	gotName := got[0].Name()
	wantName := "os/snap" // os/homebrew is for Mac only
	if gotName != wantName {
		t.Fatalf("el.FilterCapabilities(%v, %v): want plugin %q, got %q", exs, capab, wantName, gotName)
	}
}

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
			wantExts: []string{"python/pdmlock", "python/pipfilelock", "python/poetrylock", "python/condameta", "python/uvlock", "python/wheelegg", "python/requirements", "python/setup"},
		},
		{
			desc:     "Remove duplicates",
			names:    []string{"python", "python"},
			wantExts: []string{"python/pdmlock", "python/pipfilelock", "python/poetrylock", "python/condameta", "python/uvlock", "python/wheelegg", "python/requirements", "python/setup"},
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
			got, err := el.ExtractorsFromNames(tc.names)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("el.ExtractorsFromNames(%v) error got diff (-want +got):\n%s", tc.names, diff)
			}
			gotNames := []string{}
			for _, e := range got {
				gotNames = append(gotNames, e.Name())
			}
			sort := func(e1, e2 string) bool { return e1 < e2 }
			if diff := cmp.Diff(tc.wantExts, gotNames, cmpopts.SortSlices(sort)); diff != "" {
				t.Errorf("el.ExtractorsFromNames(%v): got diff (-want +got):\n%s", tc.names, diff)
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
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := el.ExtractorFromName(tc.name)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("el.ExtractorFromName(%v) error got diff (-want +got):\n%s", tc.name, diff)
			}
			if err != nil {
				return
			}
			if tc.wantExt != got.Name() {
				t.Errorf("el.ExtractorFromName(%s): want %s, got %s", tc.name, tc.wantExt, got.Name())
			}
		})
	}
}
