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

package materialize_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/enricher/reachability/javascript/materialize"
)

func TestMaterialize_GateOnExistingNodeModules(t *testing.T) {
	proj := t.TempDir()
	existing := filepath.Join(proj, "node_modules")
	if err := os.Mkdir(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	layout, err := materialize.Materialize(context.Background(), materialize.Spec{
		SubprojectRoot: proj,
	})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if layout.NodeModulesPath != existing {
		t.Errorf("NodeModulesPath = %q, want %q", layout.NodeModulesPath, existing)
	}
	if layout.CreatedByUs {
		t.Error("CreatedByUs must be false for pre-existing node_modules")
	}
}

func TestMaterialize_NoGraphMeansNoOp(t *testing.T) {
	proj := t.TempDir()
	_, err := materialize.Materialize(context.Background(), materialize.Spec{
		SubprojectRoot: proj,
	})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
}

func TestComputePlacements_SingleRootPackage(t *testing.T) {
	nm := filepath.Join("/proj", "node_modules")
	metas := []*materialize.PackageMeta{
		{Name: "lodash", Dir: "/stage/lodash@4", Parents: []int{0}},
	}
	placements := materialize.ComputePlacements(metas, nm)
	if len(placements) != 1 {
		t.Fatalf("want 1 placement, got %d", len(placements))
	}
	want := filepath.Join(nm, "lodash")
	if len(placements[0].TargetPaths) != 1 || placements[0].TargetPaths[0] != want {
		t.Errorf("want top-level placement %q, got %v", want, placements[0].TargetPaths)
	}
}

func TestComputePlacements_HoistThroughTwoLevels(t *testing.T) {
	// Both mid and leaf are root direct deps in this fixture (Parents=[0]).
	// Both should land at top-level.
	nm := filepath.Join("/proj", "node_modules")
	metas := []*materialize.PackageMeta{
		{Name: "mid", Dir: "/s/mid", Parents: []int{0}, PackageJSONDeps: map[string]string{"leaf": "1.0"}},
		{Name: "leaf", Dir: "/s/leaf", Parents: []int{0}},
	}
	placements := materialize.ComputePlacements(metas, nm)
	targetSet := map[string]bool{}
	for _, p := range placements {
		for _, tp := range p.TargetPaths {
			targetSet[tp] = true
		}
	}
	for _, name := range []string{"mid", "leaf"} {
		if !targetSet[filepath.Join(nm, name)] {
			t.Errorf("%s missing top-level; have %v", name, targetSet)
		}
	}
}

func TestComputePlacements_NestOnVersionConflict(t *testing.T) {
	// Two mids depend on different versions of leaf → nest under each.
	// Parents convention: positive N means metas[N-1].
	nm := filepath.Join("/proj", "node_modules")
	metas := []*materialize.PackageMeta{
		{Name: "mid1", Dir: "/s/mid1", Parents: []int{0},
			PackageJSONDeps: map[string]string{"leaf": "1.0"}},
		{Name: "mid2", Dir: "/s/mid2", Parents: []int{0},
			PackageJSONDeps: map[string]string{"leaf": "2.0"}},
		{Name: "leaf", Version: "1.0", Dir: "/s/leaf1", Parents: []int{1}}, // mid1
		{Name: "leaf", Version: "2.0", Dir: "/s/leaf2", Parents: []int{2}}, // mid2
	}
	placements := materialize.ComputePlacements(metas, nm)
	var paths []string
	for _, p := range placements {
		paths = append(paths, p.TargetPaths...)
	}
	sort.Strings(paths)
	want := []string{
		filepath.Join(nm, "mid1"),
		filepath.Join(nm, "mid1", "node_modules", "leaf"),
		filepath.Join(nm, "mid2"),
		filepath.Join(nm, "mid2", "node_modules", "leaf"),
	}
	for _, w := range want {
		if !slices.Contains(paths, w) {
			t.Errorf("missing expected path %q in %v", w, paths)
		}
	}
}

func TestTarjanSCC_HandlesCycles(t *testing.T) {
	// a ↔ b cycle. Per the offset convention, Parents=[N] means metas[N-1].
	// To encode "a's parent is b" → Parents=[2]; "b's parent is a" → Parents=[1].
	metas := []*materialize.PackageMeta{
		{Name: "a", Parents: []int{2}}, // parent = metas[1] = b
		{Name: "b", Parents: []int{1}}, // parent = metas[0] = a
	}
	sccs := materialize.TarjanSCC(metas)
	if len(sccs) != 1 {
		t.Errorf("want 1 SCC, got %d (%v)", len(sccs), sccs)
	}
}

func TestComputePlacements_NpmAlias(t *testing.T) {
	// parent declares `"alias-name": "npm:real@1.0"`, real package has
	// Name="real". Install location should be under "alias-name".
	metas := []*materialize.PackageMeta{
		{Name: "parent", Dir: "/s/parent", Parents: []int{0},
			PackageJSONDeps: map[string]string{"alias-name": "npm:real@1.0"}},
		{Name: "real", Version: "1.0", Dir: "/s/real", Parents: []int{1}},
	}
	placements := materialize.ComputePlacements(metas, "/proj/node_modules")
	found := false
	for _, p := range placements {
		for _, tp := range p.TargetPaths {
			if strings.Contains(tp, "alias-name") {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected at least one placement under the alias name")
	}
}

func makeFakeTarball(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		hdr := &tar.Header{
			Name:     "package/" + name, // npm strip-components=1
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(tw, bytes.NewReader([]byte(content))); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExtractTarball_StripsPackagePrefix(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "pkg.tgz")
	makeFakeTarball(t, tarPath, map[string]string{
		"index.js":    "module.exports = 1;",
		"lib/util.js": "module.exports = 2;",
	})
	out := filepath.Join(dir, "extracted")
	if err := materialize.ExtractTarball(tarPath, out); err != nil {
		t.Fatalf("ExtractTarball: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(out, "index.js"))
	if err != nil || string(b) != "module.exports = 1;" {
		t.Errorf("index.js content wrong: %q err=%v", b, err)
	}
	b, err = os.ReadFile(filepath.Join(out, "lib", "util.js"))
	if err != nil || string(b) != "module.exports = 2;" {
		t.Errorf("lib/util.js content wrong: %q err=%v", b, err)
	}
}

func TestHardlinkTree_PreservesContent(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "hl")
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "b.txt"), []byte("world"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := materialize.HardlinkTree(src, dst); err != nil {
		t.Fatalf("HardlinkTree: %v", err)
	}
	b1, _ := os.ReadFile(filepath.Join(dst, "a.txt"))
	b2, _ := os.ReadFile(filepath.Join(dst, "sub", "b.txt"))
	if string(b1) != "hello" || string(b2) != "world" {
		t.Errorf("hard-linked content wrong: %q %q", b1, b2)
	}
}

func TestHardlinkTree_SkipsNestedNodeModules(t *testing.T) {
	src := t.TempDir()
	_ = os.MkdirAll(filepath.Join(src, "node_modules", "nested"), 0o755)
	_ = os.WriteFile(filepath.Join(src, "node_modules", "nested", "x.js"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(src, "main.js"), []byte("m"), 0o644)

	dst := filepath.Join(t.TempDir(), "hl")
	if err := materialize.HardlinkTree(src, dst); err != nil {
		t.Fatalf("HardlinkTree: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "main.js")); err != nil {
		t.Errorf("main.js missing from dst")
	}
	if _, err := os.Stat(filepath.Join(dst, "node_modules")); err == nil {
		t.Errorf("nested node_modules should have been skipped")
	}
}
