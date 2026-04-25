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

package suggest

import (
	"reflect"
	"sort"
	"testing"

	"deps.dev/util/resolve"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
)

type testPythonManifest struct {
	filePath     string
	root         resolve.Version
	requirements []resolve.RequirementVersion
	groups       map[manifest.RequirementKey][]string
}

func (m testPythonManifest) FilePath() string                                      { return m.filePath }
func (m testPythonManifest) Root() resolve.Version                                 { return m.root }
func (m testPythonManifest) System() resolve.System                                { return resolve.PyPI }
func (m testPythonManifest) Requirements() []resolve.RequirementVersion            { return m.requirements }
func (m testPythonManifest) Groups() map[manifest.RequirementKey][]string          { return m.groups }
func (m testPythonManifest) LocalManifests() []manifest.Manifest                   { return nil }
func (m testPythonManifest) EcosystemSpecific() any                                { return nil }
func (m testPythonManifest) PatchRequirement(req resolve.RequirementVersion) error { return nil }
func (m testPythonManifest) Clone() manifest.Manifest                              { return m }

func TestPythonSuggest(t *testing.T) {
	ctx := t.Context()
	lc := resolve.NewLocalClient()

	pk1 := resolve.PackageKey{System: resolve.PyPI, Name: "pkg1"}
	for _, v := range []string{"1.0.0", "1.0.1", "1.1.0", "2.0.0"} {
		lc.AddVersion(resolve.Version{VersionKey: resolve.VersionKey{PackageKey: pk1, Version: v, VersionType: resolve.Concrete}}, nil)
	}
	pk2 := resolve.PackageKey{System: resolve.PyPI, Name: "pkg2"}
	for _, v := range []string{"1.0.0", "1.1.0", "1.1.1", "1.2.0"} {
		lc.AddVersion(resolve.Version{VersionKey: resolve.VersionKey{PackageKey: pk2, Version: v, VersionType: resolve.Concrete}}, nil)
	}
	pk3 := resolve.PackageKey{System: resolve.PyPI, Name: "pkg3"}
	for _, v := range []string{"1.0.0", "1.1.0-alpha", "1.1.0"} {
		lc.AddVersion(resolve.Version{VersionKey: resolve.VersionKey{PackageKey: pk3, Version: v, VersionType: resolve.Concrete}}, nil)
	}

	mf := testPythonManifest{
		requirements: []resolve.RequirementVersion{
			{VersionKey: resolve.VersionKey{PackageKey: pk1, Version: "==1.0.0", VersionType: resolve.Requirement}},
			{VersionKey: resolve.VersionKey{PackageKey: pk2, Version: ">=1.0.0,<1.2.0", VersionType: resolve.Requirement}},
			{VersionKey: resolve.VersionKey{PackageKey: pk3, Version: "==1.0.0", VersionType: resolve.Requirement}},
		},
		groups: make(map[manifest.RequirementKey][]string),
	}

	tests := []struct {
		name string
		opts options.UpdateOptions
		want result.Patch
	}{
		{
			name: "upgrade all to major",
			opts: func() options.UpdateOptions {
				cfg := upgrade.NewConfig()
				cfg.SetDefault(upgrade.Major)
				return options.UpdateOptions{
					ResolveClient: lc,
					UpgradeConfig: cfg,
				}
			}(),
			want: result.Patch{
				PackageUpdates: []result.PackageUpdate{
					{Name: "pkg1", VersionFrom: "==1.0.0", VersionTo: "==2.0.0"},
					{Name: "pkg2", VersionFrom: ">=1.0.0,<1.2.0", VersionTo: "==1.2.0"},
					{Name: "pkg3", VersionFrom: "==1.0.0", VersionTo: "==1.1.0"},
				},
			},
		},
		{
			name: "upgrade all to minor",
			opts: func() options.UpdateOptions {
				cfg := upgrade.NewConfig()
				cfg.SetDefault(upgrade.Minor)
				return options.UpdateOptions{
					ResolveClient: lc,
					UpgradeConfig: cfg,
				}
			}(),
			want: result.Patch{
				PackageUpdates: []result.PackageUpdate{
					{Name: "pkg1", VersionFrom: "==1.0.0", VersionTo: "==1.1.0"},
					{Name: "pkg2", VersionFrom: ">=1.0.0,<1.2.0", VersionTo: "==1.2.0"},
					{Name: "pkg3", VersionFrom: "==1.0.0", VersionTo: "==1.1.0"},
				},
			},
		},
		{
			name: "upgrade all to patch",
			opts: func() options.UpdateOptions {
				cfg := upgrade.NewConfig()
				cfg.SetDefault(upgrade.Patch)
				return options.UpdateOptions{
					ResolveClient: lc,
					UpgradeConfig: cfg,
				}
			}(),
			want: result.Patch{
				PackageUpdates: []result.PackageUpdate{
					{Name: "pkg1", VersionFrom: "==1.0.0", VersionTo: "==1.0.1"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (&PythonSuggester{}).Suggest(ctx, mf, tt.opts)
			if err != nil {
				t.Fatalf("PythonSuggester.Suggest() error = %v", err)
			}
			sort.Slice(got.PackageUpdates, func(i, j int) bool {
				return got.PackageUpdates[i].Name < got.PackageUpdates[j].Name
			})
			sort.Slice(tt.want.PackageUpdates, func(i, j int) bool {
				return tt.want.PackageUpdates[i].Name < tt.want.PackageUpdates[j].Name
			})
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("PythonSuggester.Suggest() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPythonSuggest_IgnoreDev(t *testing.T) {
	ctx := t.Context()
	lc := resolve.NewLocalClient()

	pk1 := resolve.PackageKey{System: resolve.PyPI, Name: "pkg1"}
	lc.AddVersion(resolve.Version{VersionKey: resolve.VersionKey{PackageKey: pk1, Version: "1.0.0", VersionType: resolve.Concrete}}, nil)
	lc.AddVersion(resolve.Version{VersionKey: resolve.VersionKey{PackageKey: pk1, Version: "1.1.0", VersionType: resolve.Concrete}}, nil)

	pk2 := resolve.PackageKey{System: resolve.PyPI, Name: "pkg2"}
	lc.AddVersion(resolve.Version{VersionKey: resolve.VersionKey{PackageKey: pk2, Version: "1.0.0", VersionType: resolve.Concrete}}, nil)
	lc.AddVersion(resolve.Version{VersionKey: resolve.VersionKey{PackageKey: pk2, Version: "1.1.0", VersionType: resolve.Concrete}}, nil)

	mf := testPythonManifest{
		requirements: []resolve.RequirementVersion{
			{VersionKey: resolve.VersionKey{PackageKey: pk1, Version: "==1.0.0", VersionType: resolve.Requirement}},
			{VersionKey: resolve.VersionKey{PackageKey: pk2, Version: "==1.0.0", VersionType: resolve.Requirement}},
		},
		groups: map[manifest.RequirementKey][]string{
			manifest.RequirementKey(pk2): {"dev"},
		},
	}

	cfg := upgrade.NewConfig()
	cfg.SetDefault(upgrade.Major)
	opts := options.UpdateOptions{
		ResolveClient: lc,
		UpgradeConfig: cfg,
		IgnoreDev:     true,
	}

	got, err := (&PythonSuggester{}).Suggest(ctx, mf, opts)
	if err != nil {
		t.Fatalf("PythonSuggester.Suggest() error = %v", err)
	}

	want := result.Patch{
		PackageUpdates: []result.PackageUpdate{
			{Name: "pkg1", VersionFrom: "==1.0.0", VersionTo: "==1.1.0"},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("PythonSuggester.Suggest() diff (-want +got):\n%s", diff)
	}
}

func TestSuggestPythonVersion(t *testing.T) {
	ctx := t.Context()
	lc := resolve.NewLocalClient()

	pk := resolve.PackageKey{
		System: resolve.PyPI,
		Name:   "pkg",
	}
	for _, version := range []string{"1.0.0", "1.0.1", "1.1.0", "2.0.0", "2.1.0-alpha.1"} {
		lc.AddVersion(resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey:  pk,
				VersionType: resolve.Concrete,
				Version:     version,
			}}, nil)
	}

	tests := []struct {
		requirement string
		level       upgrade.Level
		want        string
	}{
		{"==1.0.0", upgrade.Major, "==2.0.0"},
		{"==1.0.0", upgrade.Minor, "==1.1.0"},
		{"==1.0.0", upgrade.Patch, "==1.0.1"},
		// Range requirement
		{">=1.0.0,<1.1.0", upgrade.Major, "==2.0.0"},
		{">=1.0.0,<1.1.0", upgrade.Minor, "==1.1.0"},
		{">=1.0.0,<1.1.0", upgrade.Patch, ">=1.0.0,<1.1.0"}, // No patch update beyond 1.0.1 (matching 1.0.1)
		// Prerelease
		{"==2.0.0", upgrade.Major, "==2.0.0"}, // 2.1.0-alpha.1 is prerelease, skip
		// Compatible release (~=)
		{"~=1.0.0", upgrade.Major, "==2.0.0"},
		{"~=1.0.0", upgrade.Minor, "==1.1.0"},
		{"~=1.0.0", upgrade.Patch, "~=1.0.0"}, // No patch update beyond 1.0.1 (matching 1.0.1)
	}

	for _, tt := range tests {
		vk := resolve.VersionKey{
			PackageKey:  pk,
			VersionType: resolve.Requirement,
			Version:     tt.requirement,
		}
		want := resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey:  pk,
				VersionType: resolve.Requirement,
				Version:     tt.want,
			},
		}
		got, err := suggestPythonVersion(ctx, lc, resolve.RequirementVersion{VersionKey: vk}, tt.level)
		if err != nil {
			t.Fatalf("fail to suggest a new version for %v: %v", vk, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("suggestPythonVersion(%v, %v): got %v want %v", vk, tt.level, got, want)
		}
	}
}
