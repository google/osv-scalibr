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

package entrypoints_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/enricher/reachability/javascript/entrypoints"
)

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestInfer_NoConfigsReturnsNil(t *testing.T) {
	root := t.TempDir()
	if got := entrypoints.Infer(root); got != nil {
		t.Errorf("want nil with no package.json/tsconfig.json, got %v", got)
	}
}

func TestInfer_PackageJSONMain(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"main":"lib/index.js"}`)
	writeFile(t, root, "lib/index.js", "")
	got := entrypoints.Infer(root)
	want := filepath.Join(root, "lib/index.js")
	if !slices.Contains(got, want) {
		t.Errorf("Infer = %v, want to contain %q", got, want)
	}
}

func TestInfer_PackageJSONBinAsString(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"bin":"bin/cli.js"}`)
	writeFile(t, root, "bin/cli.js", "")
	got := entrypoints.Infer(root)
	want := filepath.Join(root, "bin/cli.js")
	if !slices.Contains(got, want) {
		t.Errorf("Infer = %v, want to contain %q", got, want)
	}
}

func TestInfer_PackageJSONBinAsMap(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"bin":{"foo":"bin/foo.js","bar":"bin/bar.js"}}`)
	writeFile(t, root, "bin/foo.js", "")
	writeFile(t, root, "bin/bar.js", "")
	got := entrypoints.Infer(root)
	for _, want := range []string{filepath.Join(root, "bin/foo.js"), filepath.Join(root, "bin/bar.js")} {
		if !slices.Contains(got, want) {
			t.Errorf("Infer missing %q in %v", want, got)
		}
	}
}

func TestInfer_PackageJSONExportsNested(t *testing.T) {
	// Conditional exports: { ".": { "import": "./a.mjs", "require": "./a.cjs" } }
	root := t.TempDir()
	writeFile(t, root, "package.json",
		`{"exports":{".":{"import":"./a.mjs","require":"./a.cjs"},"./util":"./util.js"}}`)
	for _, f := range []string{"a.mjs", "a.cjs", "util.js"} {
		writeFile(t, root, f, "")
	}
	got := entrypoints.Infer(root)
	for _, want := range []string{filepath.Join(root, "a.mjs"), filepath.Join(root, "a.cjs"), filepath.Join(root, "util.js")} {
		if !slices.Contains(got, want) {
			t.Errorf("Infer missing %q in %v", want, got)
		}
	}
}

func TestInfer_AcceptsDeclaredButNotYetExisting(t *testing.T) {
	// `main` points to a path that doesn't exist on disk yet. Common in
	// pre-build / freshly-cloned projects: package.json declares
	// `dist/index.js` but `npm run build` hasn't generated it.
	// The lexical-containment pre-check already proves the declared
	// path is under projectRoot, so it's safe to hand to jelly —
	// jelly's own file open will surface the missing-file error
	// without escaping the project root. Dropping the entry would
	// silently widen jelly to a whole-project scan.
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"main":"dist/index.js"}`)
	got := entrypoints.Infer(root)
	want := filepath.Join(root, "dist/index.js")
	if !slices.Contains(got, want) {
		t.Errorf("Infer should accept declared-but-not-yet-existing in-tree paths; got %v, want to contain %q", got, want)
	}
}

func TestInfer_RejectsMissingPathThatEscapes(t *testing.T) {
	// Even when the path doesn't exist, escape attempts via ../ must
	// still be rejected by the lexical pre-check.
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"main":"../../etc/hostname"}`)
	got := entrypoints.Infer(root)
	for _, p := range got {
		if !strings.HasPrefix(p, root+string(filepath.Separator)) && p != root {
			t.Errorf("escape via missing path: %q is outside project root %q", p, root)
		}
	}
}

func TestInfer_TSConfigFilesAndIncludeStripsGlobs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "tsconfig.json", `{
	  // line comments are tolerated
	  "files": ["src/main.ts"],
	  "include": ["src/**/*", "tests/setup.ts"]
	}`)
	writeFile(t, root, "src/main.ts", "")
	writeFile(t, root, "src/extra.ts", "")
	writeFile(t, root, "tests/setup.ts", "")
	got := entrypoints.Infer(root)
	// Glob "src/**/*" should be reduced to its prefix "src".
	for _, want := range []string{
		filepath.Join(root, "src/main.ts"),
		filepath.Join(root, "src"),
		filepath.Join(root, "tests/setup.ts"),
	} {
		if !slices.Contains(got, want) {
			t.Errorf("Infer missing %q in %v", want, got)
		}
	}
}

func TestInfer_RejectsPathsEscapingProjectRoot(t *testing.T) {
	// Defense: a malicious or corrupt package.json can declare main as
	// "../../etc/hostname". filepath.Join cleans this to /etc/hostname,
	// which os.Stat may succeed on. The containment check must drop it
	// before jelly sees it as an entry point.
	root := t.TempDir()
	// Use a real file outside root that absolutely exists on Linux: the
	// project's own go.mod via a relative escape. Picking a path we
	// EXPECT to be outside root is fine for the test.
	writeFile(t, root, "package.json", `{"main":"../../etc/hostname"}`)
	got := entrypoints.Infer(root)
	for _, p := range got {
		if !strings.HasPrefix(p, root+string(filepath.Separator)) && p != root {
			t.Errorf("entry point %q escapes project root %q", p, root)
		}
	}
}

func TestInfer_Deduplicates(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"main":"lib/index.js","module":"lib/index.js"}`)
	writeFile(t, root, "lib/index.js", "")
	got := entrypoints.Infer(root)
	count := 0
	want := filepath.Join(root, "lib/index.js")
	for _, p := range got {
		if p == want {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 occurrence of %q, got %d in %v", want, count, got)
	}
}
