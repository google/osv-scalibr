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

package python

import (
	"testing"

	"deps.dev/util/resolve"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
)

type testManifest struct {
	FilePath     string
	Root         resolve.Version
	System       resolve.System
	Requirements []resolve.RequirementVersion
	Groups       map[manifest.RequirementKey][]string
}

func checkManifest(t *testing.T, name string, got manifest.Manifest, want testManifest) {
	t.Helper()
	if want.FilePath != got.FilePath() {
		t.Errorf("%s.FilePath() = %q, want %q", name, got.FilePath(), want.FilePath)
	}
	if diff := cmp.Diff(want.Root, got.Root()); diff != "" {
		t.Errorf("%s.Root() (-want +got):\n%s", name, diff)
	}
	if want.System != got.System() {
		t.Errorf("%s.System() = %v, want %v", name, got.System(), want.System)
	}
	if diff := cmp.Diff(want.Requirements, got.Requirements()); diff != "" {
		t.Errorf("%s.Requirements() (-want +got):\n%s", name, diff)
	}
	if diff := cmp.Diff(want.Groups, got.Groups()); diff != "" {
		t.Errorf("%s.Groups() (-want +got):\n%s", name, diff)
	}
}
