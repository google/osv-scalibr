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

package relaxer_test

import (
	"testing"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/guidedremediation/internal/strategy/relax/relaxer"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
)

func TestRelaxPython(t *testing.T) {
	type result struct {
		version string
		ok      bool
	}
	tests := []struct {
		name          string
		versions      []string
		from          string
		upgradeConfig upgrade.Config
		want          result
	}{
		{
			name:          "pinned version to pinned version",
			versions:      []string{"1.2.3", "1.2.4", "1.2.5", "1.3.0", "1.4.0", "2.0.0"},
			from:          "==1.2.3",
			upgradeConfig: upgrade.Config{"": upgrade.Major},
			want: result{
				version: "==1.2.5",
				ok:      true,
			},
		},
		{
			name:          "relaxed pinned version disallowed",
			versions:      []string{"1.2.3", "1.2.4", "1.2.5", "1.3.0", "1.4.0", "2.0.0"},
			from:          "==1.3.0",
			upgradeConfig: upgrade.Config{"": upgrade.Patch},
			want: result{
				version: "==1.3.0",
				ok:      false,
			},
		},
		{
			name:          "relax to compatible release",
			versions:      []string{"1.2.3", "1.2.4", "1.2.5", "1.3.0", "1.4.0", "2.0.0"},
			from:          ">=1.2.3,<1.2.5",
			upgradeConfig: upgrade.Config{"": upgrade.Major},
			want: result{
				version: "~=1.2.5",
				ok:      true,
			},
		},
		{
			name:          "relax to version range",
			versions:      []string{"1.2.3", "1.2.4", "1.2.5", "1.3.0", "1.4.0", "2.0.0"},
			from:          "~=1.2.3",
			upgradeConfig: upgrade.Config{"": upgrade.Major},
			want: result{
				version: ">=1.3.0,<2.0.0",
				ok:      true,
			},
		},
		{
			name:          "relax to a major version",
			versions:      []string{"1.2.3", "1.2.4", "1.2.5", "1.3.0", "1.4.0", "2.0.0"},
			from:          ">=1.2.3,<2.0.0",
			upgradeConfig: upgrade.Config{"": upgrade.Major},
			want: result{
				version: ">=2.0.0,<3.0.0",
				ok:      true,
			},
		},
		{
			name:          "no newer version",
			versions:      []string{"1.2.3", "1.2.4", "1.2.5"},
			from:          "~=1.2.5",
			upgradeConfig: upgrade.Config{"": upgrade.Major},
			want: result{
				version: "~=1.2.5",
				ok:      false,
			},
		},
		{
			name:          "skip the missing major",
			versions:      []string{"1.0.0", "3.0.0", "4.0.0"},
			from:          "~=1.0.0",
			upgradeConfig: upgrade.Config{"": upgrade.Major},
			want: result{
				version: ">=3.0.0,<4.0.0",
				ok:      true,
			},
		},
		{
			name:          "skip pre-release",
			versions:      []string{"1.2.3", "2.0.0-alpha", "2.0.0", "3.0.0"},
			from:          ">=1.0.0,<2.0.0",
			upgradeConfig: upgrade.Config{"": upgrade.Major},
			want: result{
				version: ">=2.0.0,<3.0.0",
				ok:      true,
			},
		},
		{
			name:          "avoid pre-release patch",
			versions:      []string{"1.2.3", "1.2.4", "1.2.5", "1.2.6-alpha"},
			from:          ">=1.2.3,<1.2.5",
			upgradeConfig: upgrade.Config{"": upgrade.Major},
			want: result{
				version: "~=1.2.5",
				ok:      true,
			},
		},
		{
			name:          "avoid pre-release minor",
			versions:      []string{"1.2.3", "1.3.4", "1.4.5-alpha"},
			from:          "~=1.2.3",
			upgradeConfig: upgrade.Config{"": upgrade.Major},
			want: result{
				version: ">=1.3.4,<2.0.0",
				ok:      true,
			},
		},
		{
			name:          "choose the latest pre-release",
			versions:      []string{"1.2.3", "2.0.0-alpha.0", "2.0.0-alpha.1", "2.0.0-beta"},
			from:          ">=1.0.0,<2.0.0",
			upgradeConfig: upgrade.Config{"": upgrade.Major},
			want: result{
				version: ">=2.0.0-beta,<3.0.0",
				ok:      true,
			},
		},
		{
			name:          "relax from pre-release",
			versions:      []string{"1.0.0-pre", "1.2.3", "2.0.0-pre", "2.3.4"},
			from:          ">=1.0.0-pre,<2.0.0",
			upgradeConfig: upgrade.Config{"": upgrade.Major},
			want: result{
				version: ">=2.3.4,<3.0.0",
				ok:      true,
			},
		},
		{
			name:          "upgrades not allowed",
			versions:      []string{"1.2.3", "1.2.4", "1.2.5", "1.3.0", "1.4.0", "2.0.0"},
			from:          "==1.2.3",
			upgradeConfig: upgrade.Config{"": upgrade.None},
			want: result{
				version: "==1.2.3",
				ok:      false,
			},
		},
		{
			name:          "major upgrades not allowed",
			versions:      []string{"1.2.3", "1.2.4", "1.2.5", "1.3.0", "1.4.0", "2.0.0"},
			from:          ">=1.2.3,<2.0.0",
			upgradeConfig: upgrade.Config{"": upgrade.Minor},
			want: result{
				version: ">=1.2.3,<2.0.0",
				ok:      false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := resolve.NewLocalClient()
			pk := resolve.PackageKey{
				Name:   "my-project",
				System: resolve.PyPI,
			}
			for _, v := range tt.versions {
				cl.AddVersion(resolve.Version{
					VersionKey: resolve.VersionKey{
						PackageKey:  pk,
						Version:     v,
						VersionType: resolve.Concrete,
					},
				}, nil)
			}

			reqRelaxer := relaxer.PythonRelaxer{}
			got, ok := reqRelaxer.Relax(t.Context(), cl, resolve.RequirementVersion{
				VersionKey: resolve.VersionKey{
					PackageKey:  pk,
					VersionType: resolve.Requirement,
					Version:     tt.from,
				}}, tt.upgradeConfig)
			if got.Version != tt.want.version || ok != tt.want.ok {
				t.Errorf("Relax() = (%s, %v), want (%s, %v)", got.Version, ok, tt.want.version, tt.want.ok)
			}
		})
	}
}
