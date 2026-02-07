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

// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package upgrade_test

import (
	"slices"
	"testing"

	"deps.dev/util/semver"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
)

func TestLevelAllows(t *testing.T) {
	// Check every combination of Level + Diff
	allDiffs := [...]semver.Diff{
		semver.Same,
		semver.DiffOther,
		semver.DiffMajor,
		semver.DiffMinor,
		semver.DiffPatch,
		semver.DiffPrerelease,
		semver.DiffBuild,
	}

	levelDisallowed := map[upgrade.Level][]semver.Diff{
		upgrade.Major: {},
		upgrade.Minor: {semver.DiffMajor},
		upgrade.Patch: {semver.DiffMajor, semver.DiffMinor},
		upgrade.None:  allDiffs[1:], // everything but semver.Same
	}

	for level, disallowed := range levelDisallowed {
		for _, diff := range allDiffs {
			want := !slices.Contains(disallowed, diff)
			got := level.Allows(diff)
			if want != got {
				t.Errorf("(Level: %v, Diff: %v) Allows() = %v, want %v", level, diff, got, want)
			}
		}
	}
}

func configSetExpect(t *testing.T, config upgrade.Config, pkg string, level upgrade.Level, want bool) {
	t.Helper()
	got := config.Set(pkg, level)
	if got != want {
		t.Errorf("Set(%v, %v) got %v, want %v", pkg, level, got, want)
	}
}

func configSetDefaultExpect(t *testing.T, config upgrade.Config, level upgrade.Level, want bool) {
	t.Helper()
	got := config.SetDefault(level)
	if got != want {
		t.Errorf("SetDefault(%v) got %v, want %v", level, got, want)
	}
}

func configGetExpect(t *testing.T, config upgrade.Config, pkg string, want upgrade.Level) {
	t.Helper()
	if got := config.Get(pkg); got != want {
		t.Errorf("Get(%v) got %v, want %v", pkg, got, want)
	}
}

func TestConfig(t *testing.T) {
	config := upgrade.NewConfig()

	// Default everything to allow major
	configGetExpect(t, config, "foo", upgrade.Major)
	configGetExpect(t, config, "bar", upgrade.Major)

	// Set specific package
	configSetExpect(t, config, "foo", upgrade.Minor, false)
	configGetExpect(t, config, "foo", upgrade.Minor)
	configGetExpect(t, config, "bar", upgrade.Major)

	// Set package again
	configSetExpect(t, config, "foo", upgrade.None, true)
	configGetExpect(t, config, "foo", upgrade.None)
	configGetExpect(t, config, "bar", upgrade.Major)

	// Set default
	configSetDefaultExpect(t, config, upgrade.Patch, false)
	configGetExpect(t, config, "foo", upgrade.None)
	configGetExpect(t, config, "bar", upgrade.Patch)

	// Set default again
	configSetDefaultExpect(t, config, upgrade.Major, true)
	configGetExpect(t, config, "foo", upgrade.None)
	configGetExpect(t, config, "bar", upgrade.Major)

	// Set other package
	configSetExpect(t, config, "bar", upgrade.Minor, false)
	configGetExpect(t, config, "foo", upgrade.None)
	configGetExpect(t, config, "bar", upgrade.Minor)
	configGetExpect(t, config, "baz", upgrade.Major)
}
