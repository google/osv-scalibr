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

package parser

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/guidedremediation/internal/manifest/npm"
)

func TestParseManifestRejectsPathOutsideProjectRoot(t *testing.T) {
	parent := t.TempDir()
	projectRoot := filepath.Join(parent, "project")
	if err := os.Mkdir(projectRoot, 0755); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(parent, "package.json")
	if err := os.WriteFile(manifestPath, []byte(`{"name":"outside","version":"1.0.0"}`), 0644); err != nil {
		t.Fatal(err)
	}
	rw, err := npm.GetReadWriter()
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseManifest(manifestPath, rw, projectRoot)
	if err == nil || !strings.Contains(err.Error(), "outside project root") {
		t.Fatalf("ParseManifest() error = %v, want outside-project-root error", err)
	}
}

func TestRootAndPathUsesNearestGitRoot(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	manifestDir := filepath.Join(repo, "module", "app")
	if err := os.MkdirAll(manifestDir, 0755); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(manifestDir, "package.json")

	root, relPath, err := rootAndPath(manifestPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	if got := root.Name(); got != repo {
		t.Fatalf("root.Name() = %q, want nearest Git root %q", got, repo)
	}
	if want := "module/app/package.json"; relPath != want {
		t.Fatalf("relative path = %q, want %q", relPath, want)
	}
}

func TestRootAndPathUsesNearestNestedGitRoot(t *testing.T) {
	outer := t.TempDir()
	if err := os.Mkdir(filepath.Join(outer, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(outer, "nested")
	if err := os.MkdirAll(filepath.Join(inner, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(inner, "package.json")

	root, _, err := rootAndPath(manifestPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	if got := root.Name(); got != inner {
		t.Fatalf("root.Name() = %q, want nearest nested Git root %q", got, inner)
	}
}

func TestRootAndPathAcceptsGitFile(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, ".git"), []byte("gitdir: elsewhere\n"), 0644); err != nil {
		t.Fatal(err)
	}
	manifestDir := filepath.Join(repo, "module")
	if err := os.Mkdir(manifestDir, 0755); err != nil {
		t.Fatal(err)
	}

	root, _, err := rootAndPath(filepath.Join(manifestDir, "package.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	if got := root.Name(); got != repo {
		t.Fatalf("root.Name() = %q, want Git worktree root %q", got, repo)
	}
}

func TestRootAndPathFallsBackToManifestDirectory(t *testing.T) {
	manifestDir := t.TempDir()
	manifestPath := filepath.Join(manifestDir, "package.json")

	root, relPath, err := rootAndPath(manifestPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	if got := root.Name(); got != manifestDir {
		t.Fatalf("root.Name() = %q, want manifest directory %q", got, manifestDir)
	}
	if relPath != "package.json" {
		t.Fatalf("relative path = %q, want %q", relPath, "package.json")
	}
}

func TestRootAndPathExplicitRootOverridesGitRoot(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	projectRoot := filepath.Join(repo, "project")
	if err := os.Mkdir(projectRoot, 0755); err != nil {
		t.Fatal(err)
	}

	root, _, err := rootAndPath(filepath.Join(projectRoot, "package.json"), projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	if got := root.Name(); got != projectRoot {
		t.Fatalf("root.Name() = %q, want explicit project root %q", got, projectRoot)
	}
}

func TestParseManifestRejectsEscapingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require additional privileges on Windows")
	}
	parent := t.TempDir()
	projectRoot := filepath.Join(parent, "project")
	if err := os.Mkdir(projectRoot, 0755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "outside.json")
	if err := os.WriteFile(outside, []byte(`{"name":"outside","version":"1.0.0"}`), 0644); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(projectRoot, "package.json")
	if err := os.Symlink(outside, manifestPath); err != nil {
		t.Fatal(err)
	}
	rw, err := npm.GetReadWriter()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseManifest(manifestPath, rw, projectRoot); err == nil {
		t.Fatal("ParseManifest() succeeded through a symlink outside the project root")
	}
}

func TestParseManifestAllowsSymlinkWithinProjectRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require additional privileges on Windows")
	}
	projectRoot := t.TempDir()
	realDir := filepath.Join(projectRoot, "real")
	if err := os.Mkdir(realDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "package.json"), []byte(`{"name":"inside","version":"1.0.0"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(projectRoot, "linked")); err != nil {
		t.Fatal(err)
	}
	rw, err := npm.GetReadWriter()
	if err != nil {
		t.Fatal(err)
	}

	m, err := ParseManifest(filepath.Join(projectRoot, "linked", "package.json"), rw, projectRoot)
	if err != nil {
		t.Fatalf("ParseManifest() rejected a symlink contained within the project root: %v", err)
	}
	if got := m.Root().Name; got != "inside" {
		t.Fatalf("manifest root name = %q, want %q", got, "inside")
	}
}

func TestParseManifestRejectsEscapingDirectorySymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require additional privileges on Windows")
	}
	parent := t.TempDir()
	projectRoot := filepath.Join(parent, "project")
	outDir := filepath.Join(parent, "outside")
	if err := os.Mkdir(projectRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "package.json"), []byte(`{"name":"outside","version":"1.0.0"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outDir, filepath.Join(projectRoot, "linked")); err != nil {
		t.Fatal(err)
	}
	rw, err := npm.GetReadWriter()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseManifest(filepath.Join(projectRoot, "linked", "package.json"), rw, projectRoot); err == nil {
		t.Fatal("ParseManifest() followed a directory symlink outside the project root")
	}
}

func TestWriteManifestRejectsEscapingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require additional privileges on Windows")
	}
	parent := t.TempDir()
	projectRoot := filepath.Join(parent, "project")
	if err := os.Mkdir(projectRoot, 0755); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(projectRoot, "package.json")
	if err := os.WriteFile(manifestPath, []byte(`{"name":"inside","version":"1.0.0"}`), 0644); err != nil {
		t.Fatal(err)
	}
	rw, err := npm.GetReadWriter()
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseManifest(manifestPath, rw, projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(parent, "outside")
	if err := os.Mkdir(outDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(manifestPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outDir, "package.json"), manifestPath); err != nil {
		t.Fatal(err)
	}

	if err := WriteManifestPatches(manifestPath, m, nil, rw, projectRoot); err == nil {
		t.Fatal("WriteManifestPatches() wrote through a symlink outside the project root")
	}
	if _, err := os.Stat(filepath.Join(outDir, "package.json")); !os.IsNotExist(err) {
		t.Fatalf("outside file exists after confined write: %v", err)
	}
}
