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

package bunlock

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestResolveDepKey(t *testing.T) {
	keys := map[string]bool{
		"a":                    true,
		"a/b":                  true,
		"a/b/c":                true,
		"c":                    true,
		"has-flag":             true,
		"@types/react-dom":     true,
		"@types/prop-types":    true,
		"x/@babel/core":        true,
		"x/@babel/core/nested": true,
	}
	tests := []struct {
		name            string
		pkgKey, depName string
		want            string
		wantOK          bool
	}{
		{name: "nested_match", pkgKey: "a/b", depName: "c", want: "a/b/c", wantOK: true},
		{name: "walk_up_to_top_level", pkgKey: "a/b", depName: "has-flag", want: "has-flag", wantOK: true},
		{name: "top_level", pkgKey: "a", depName: "c", want: "c", wantOK: true},
		{name: "miss", pkgKey: "a/b", depName: "missing", want: "", wantOK: false},
		{name: "self_edge_blocked", pkgKey: "c", depName: "c", want: "", wantOK: false},
		{name: "scoped_dep_from_root", pkgKey: "", depName: "@types/prop-types", want: "@types/prop-types", wantOK: true},
		{
			// Bare "prop-types" from a scoped parent must not match
			// "@types/prop-types" via a half-stripped "@types" prefix.
			name: "scoped_parent_does_not_leak_scope_prefix", pkgKey: "@types/react-dom", depName: "prop-types",
			want: "", wantOK: false,
		},
		{name: "nested_under_scoped_segment", pkgKey: "x/@babel/core", depName: "nested", want: "x/@babel/core/nested", wantOK: true},
		{name: "scoped_segment_stripped_whole", pkgKey: "x/@babel/core", depName: "has-flag", want: "has-flag", wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := resolveDepKey(tt.pkgKey, tt.depName, keys)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("resolveDepKey(%q, %q) = (%q, %v), want (%q, %v)", tt.pkgKey, tt.depName, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestPackageDependencies(t *testing.T) {
	tests := []struct {
		name                             string
		pkgs                             []any
		wantDeps, wantOptional, wantPeer map[string]string
	}{
		{
			name: "registry_tuple",
			pkgs: []any{"a@1.0.0", "", map[string]any{
				"dependencies":         map[string]any{"b": "^1.0.0"},
				"optionalDependencies": map[string]any{"c": "^2.0.0"},
				"peerDependencies":     map[string]any{"d": "*"},
			}, "sha512-..."},
			wantDeps:     map[string]string{"b": "^1.0.0"},
			wantOptional: map[string]string{"c": "^2.0.0"},
			wantPeer:     map[string]string{"d": "*"},
		},
		{
			name:     "git_tuple_with_metadata_at_index_1",
			pkgs:     []any{"a@github:o/r#abc", map[string]any{"dependencies": map[string]any{"b": "^1.0.0"}}, "marker"},
			wantDeps: map[string]string{"b": "^1.0.0"},
		},
		{
			name: "file_tuple_with_empty_metadata",
			pkgs: []any{"a@file:deps/a", map[string]any{}},
		},
		{
			name: "workspace_tuple_without_metadata",
			pkgs: []any{"a@workspace:packages/a"},
		},
		{
			name:     "non_string_dep_values_skipped",
			pkgs:     []any{"a@1.0.0", "", map[string]any{"dependencies": map[string]any{"b": "^1.0.0", "c": 1}}, "sha512-..."},
			wantDeps: map[string]string{"b": "^1.0.0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, optional, peer := packageDependencies(tt.pkgs)
			if diff := cmp.Diff(tt.wantDeps, deps); diff != "" {
				t.Errorf("dependencies diff (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantOptional, optional); diff != "" {
				t.Errorf("optionalDependencies diff (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantPeer, peer); diff != "" {
				t.Errorf("peerDependencies diff (-want +got):\n%s", diff)
			}
		})
	}
}
