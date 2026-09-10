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

package depgraph_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/enricher/reachability/javascript/depgraph"
)

// writePkg materializes a minimal package.json at the given path. Caller
// owns mkdir for the parent dir.
func writePkg(t *testing.T, path, name, version string, deps map[string]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString(`{"name":"`)
	b.WriteString(name)
	b.WriteString(`","version":"`)
	b.WriteString(version)
	b.WriteString(`"`)
	if len(deps) > 0 {
		b.WriteString(`,"dependencies":{`)
		first := true
		for k, v := range deps {
			if !first {
				b.WriteByte(',')
			}
			first = false
			b.WriteString(`"`)
			b.WriteString(k)
			b.WriteString(`":"`)
			b.WriteString(v)
			b.WriteString(`"`)
		}
		b.WriteByte('}')
	}
	b.WriteByte('}')
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBuild_FlatLayout(t *testing.T) {
	root := t.TempDir()
	writePkg(t, filepath.Join(root, "package.json"), "rootapp", "1.0.0", map[string]string{
		"a": "^1.0.0", "b": "^1.0.0",
	})
	writePkg(t, filepath.Join(root, "node_modules", "a", "package.json"), "a", "1.0.0", map[string]string{"c": "^1.0.0"})
	writePkg(t, filepath.Join(root, "node_modules", "b", "package.json"), "b", "1.0.0", nil)
	writePkg(t, filepath.Join(root, "node_modules", "c", "package.json"), "c", "1.0.0", nil)

	g, err := depgraph.Build(root)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if g == nil {
		t.Fatal("Build returned nil graph")
	}
	if len(g.Nodes) != 3 {
		t.Errorf("want 3 nodes, got %d: %v", len(g.Nodes), g.Nodes)
	}
	if len(g.Roots) != 2 {
		t.Errorf("want 2 roots, got %d: %v", len(g.Roots), g.Roots)
	}
	if !slices.Contains(g.Roots, "a@1.0.0") || !slices.Contains(g.Roots, "b@1.0.0") {
		t.Errorf("expected a@1.0.0 and b@1.0.0 in roots, got %v", g.Roots)
	}
	a := g.Nodes["a@1.0.0"]
	if !slices.Contains(a.Dependencies, "c@1.0.0") {
		t.Errorf("a should depend on c@1.0.0, got %v", a.Dependencies)
	}
}

func TestBuild_NestedMultiVersion(t *testing.T) {
	// Two versions of "semver" — one hoisted at the top, one nested
	// because parent forces a different version.
	root := t.TempDir()
	writePkg(t, filepath.Join(root, "package.json"), "rootapp", "1.0.0", map[string]string{
		"pkg-a": "^1.0.0", "pkg-b": "^1.0.0",
	})
	writePkg(t, filepath.Join(root, "node_modules", "pkg-a", "package.json"), "pkg-a", "1.0.0", map[string]string{"semver": "^7.0.0"})
	writePkg(t, filepath.Join(root, "node_modules", "pkg-b", "package.json"), "pkg-b", "1.0.0", map[string]string{"semver": "^6.0.0"})
	writePkg(t, filepath.Join(root, "node_modules", "semver", "package.json"), "semver", "7.5.0", nil)
	writePkg(t, filepath.Join(root, "node_modules", "pkg-b", "node_modules", "semver", "package.json"), "semver", "6.3.0", nil)

	g, err := depgraph.Build(root)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, ok := g.Nodes["semver@7.5.0"]; !ok {
		t.Errorf("missing semver@7.5.0; have %v", keys(g))
	}
	if _, ok := g.Nodes["semver@6.3.0"]; !ok {
		t.Errorf("missing semver@6.3.0; have %v", keys(g))
	}
	// pkg-a/semver should resolve to 7.5.0 (hoisted), pkg-b/semver to 6.3.0
	// (nested) — that's npm's actual resolution.
	if got := g.Nodes["pkg-a@1.0.0"].Dependencies; !slices.Contains(got, "semver@7.5.0") {
		t.Errorf("pkg-a → expected semver@7.5.0, got %v", got)
	}
	if got := g.Nodes["pkg-b@1.0.0"].Dependencies; !slices.Contains(got, "semver@6.3.0") {
		t.Errorf("pkg-b → expected semver@6.3.0, got %v", got)
	}
}

func TestBuild_ScopedPackage(t *testing.T) {
	root := t.TempDir()
	writePkg(t, filepath.Join(root, "package.json"), "rootapp", "1.0.0", map[string]string{
		"@scope/pkg": "^1.0.0",
	})
	writePkg(t, filepath.Join(root, "node_modules", "@scope", "pkg", "package.json"), "@scope/pkg", "1.0.0", nil)

	g, err := depgraph.Build(root)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, ok := g.Nodes["@scope/pkg@1.0.0"]; !ok {
		t.Errorf("scoped package missing; have %v", keys(g))
	}
}

func TestBuild_NoNodeModulesReturnsNilNil(t *testing.T) {
	root := t.TempDir()
	g, err := depgraph.Build(root)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if g != nil {
		t.Errorf("want nil graph when node_modules absent, got %v", g)
	}
}

func TestPathsToLeaf_ExcludesLeafAndUnreachable(t *testing.T) {
	root := t.TempDir()
	writePkg(t, filepath.Join(root, "package.json"), "rootapp", "1.0.0", map[string]string{
		"reachable-root": "^1.0.0", "unrelated": "^1.0.0",
	})
	writePkg(t, filepath.Join(root, "node_modules", "reachable-root", "package.json"), "reachable-root", "1.0.0", map[string]string{
		"middle": "^1.0.0",
	})
	writePkg(t, filepath.Join(root, "node_modules", "middle", "package.json"), "middle", "1.0.0", map[string]string{
		"vulnpkg": "^1.0.0",
	})
	writePkg(t, filepath.Join(root, "node_modules", "vulnpkg", "package.json"), "vulnpkg", "1.0.0", nil)
	writePkg(t, filepath.Join(root, "node_modules", "unrelated", "package.json"), "unrelated", "1.0.0", nil)

	g, err := depgraph.Build(root)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got := g.PathsToLeaf("vulnpkg")
	want := map[string]bool{"reachable-root": true, "middle": true}
	if len(got) != len(want) {
		t.Fatalf("PathsToLeaf len = %d, want %d (got=%v)", len(got), len(want), got)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected package on path: %q", p)
		}
	}
	if slices.Contains(got, "vulnpkg") {
		t.Error("leaf must be excluded from PathsToLeaf result")
	}
	if slices.Contains(got, "unrelated") {
		t.Error("unrelated package must not appear in path result")
	}
}

func TestIsReachableKey_DistinguishesVersions(t *testing.T) {
	// Multi-version setup: foo@1.0.0 reachable from root via direct dep,
	// foo@2.0.0 nested under bar but bar is unreachable (no root path).
	// Name-only IsReachable would say "reachable" for both; IsReachableKey
	// must distinguish so a vuln on the orphan version isn't analyzed
	// against the reachable copy's code.
	root := t.TempDir()
	writePkg(t, filepath.Join(root, "package.json"), "app", "1.0.0", map[string]string{
		"foo": "^1.0.0", // direct dep at top
	})
	writePkg(t, filepath.Join(root, "node_modules", "foo", "package.json"), "foo", "1.0.0", nil)
	// bar exists in the tree but root doesn't depend on it → orphan.
	writePkg(t, filepath.Join(root, "node_modules", "bar", "package.json"), "bar", "1.0.0", map[string]string{
		"foo": "^2.0.0",
	})
	writePkg(t, filepath.Join(root, "node_modules", "bar", "node_modules", "foo", "package.json"), "foo", "2.0.0", nil)

	g, err := depgraph.Build(root)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !g.IsReachable("foo") {
		t.Errorf("name-only IsReachable(foo) should be true (1.0.0 is reachable)")
	}
	if !g.IsReachableKey("foo", "1.0.0") {
		t.Errorf("IsReachableKey(foo, 1.0.0) should be true")
	}
	if g.IsReachableKey("foo", "2.0.0") {
		t.Errorf("IsReachableKey(foo, 2.0.0) should be false — bar is an orphan, foo@2 is unreachable via bar")
	}
}

func TestPathsToLeaf_AbsentLeafReturnsEmpty(t *testing.T) {
	root := t.TempDir()
	writePkg(t, filepath.Join(root, "package.json"), "r", "1.0.0", map[string]string{"a": "^1.0.0"})
	writePkg(t, filepath.Join(root, "node_modules", "a", "package.json"), "a", "1.0.0", nil)
	g, err := depgraph.Build(root)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := g.PathsToLeaf("not-installed"); len(got) != 0 {
		t.Errorf("PathsToLeaf on absent leaf = %v, want []", got)
	}
}

func keys(g *depgraph.Graph) []string {
	out := make([]string, 0, len(g.Nodes))
	for k := range g.Nodes {
		out = append(out, k)
	}
	return out
}
