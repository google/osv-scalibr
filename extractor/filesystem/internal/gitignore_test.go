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

package internal

import (
	"os"
	"path/filepath"
	"testing"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

// buildFS materializes files into a fresh temp directory and returns an FS
// rooted there. A nil value creates an (empty) directory; this is used to
// create ".git" markers, which -- unlike the rest of this package's
// testdata -- can't be checked into the repository itself: git refuses to
// track, clone or apply a path with a literal ".git" path component.
func buildFS(t *testing.T, files map[string][]byte) scalibrfs.FS {
	t.Helper()
	root := t.TempDir()
	for p, content := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if content == nil {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatalf("os.MkdirAll(%q): %v", full, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("os.MkdirAll(%q): %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, content, 0o644); err != nil {
			t.Fatalf("os.WriteFile(%q): %v", full, err)
		}
	}
	return scalibrfs.DirFS(root)
}

func TestGitignoreMatch(t *testing.T) {
	tests := []struct {
		name      string
		path      []string
		wantMatch bool
	}{
		{
			name:      "No_match",
			path:      []string{"testdata", "path", "to", "file.py"},
			wantMatch: false,
		},
		{
			name:      "Match_specific_name",
			path:      []string{"testdata", "path", "to", "ignore.txt"},
			wantMatch: true,
		},
		{
			name:      "Match_wildcard",
			path:      []string{"testdata", "path", "to", "file-ignore"},
			wantMatch: true,
		},
		{
			name:      "Comments_ignored",
			path:      []string{"testdata", "#file"},
			wantMatch: false,
		},
	}

	pattern, err := ParseDirForGitignore(scalibrfs.DirFS("."), "testdata")
	if err != nil {
		t.Fatalf("ParseDirForGitignore(testdata): %v", err)
	}
	patterns := []GitignorePattern{pattern}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GitignoreMatch(patterns, tt.path, false)
			if got != tt.wantMatch {
				t.Errorf("GitignoreMatch(%v): got %v, want %v", patterns, got, tt.wantMatch)
			}
		})
	}
}

func TestParseDirForGitignoreFileDoesntExist(t *testing.T) {
	_, err := ParseDirForGitignore(scalibrfs.DirFS("."), "testdata/nonexistent")
	if err != nil {
		t.Fatalf("ParseDirForGitignore(testdata/nonexistent): %v", err)
	}
}

func TestFindParentGitignores(t *testing.T) {
	tests := []struct {
		name      string
		path      []string
		wantMatch bool
	}{
		{
			name:      "No_match",
			path:      []string{"repo", "path", "to", "file.py"},
			wantMatch: false,
		},
		{
			name:      "Match_pattern_from_parent_dir",
			path:      []string{"repo", "path", "to", "ignore.txt"},
			wantMatch: true,
		},
		{
			name:      "Dont_match_pattern_from_child_dir",
			path:      []string{"repo", "subdir", "path", "to", "ignore2.txt"},
			wantMatch: false,
		},
	}

	// repo/.git marks repo as a repository root so the ancestor .gitignore
	// files below are actually considered applicable.
	fsys := buildFS(t, map[string][]byte{
		"repo/.git":              nil,
		"repo/.gitignore":        []byte("**/*-ignore\n# Comment\n\nignore.txt\n"),
		"repo/subdir/.gitignore": []byte("ignore2.txt\n"),
	})
	patterns, repoRootDepth, err := ParseParentGitignores(fsys, "repo/subdir")
	if err != nil {
		t.Fatalf("ParseParentGitignores(repo/subdir): %v", err)
	}
	if repoRootDepth < 0 {
		t.Fatalf("ParseParentGitignores(repo/subdir) repoRootDepth = %d, want >= 0", repoRootDepth)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GitignoreMatch(patterns, tt.path, false)
			if got != tt.wantMatch {
				t.Errorf("GitignoreMatch(%v): got %v, want %v", patterns, got, tt.wantMatch)
			}
		})
	}
}

func TestParseParentGitignoresOutsideRepository(t *testing.T) {
	// No .git anywhere above "outside", so outside/.gitignore must not apply:
	// applying .gitignore files found outside of a git repository is one half
	// of google/osv-scalibr#902.
	fsys := buildFS(t, map[string][]byte{
		"outside/.gitignore": []byte("ignore.txt\n"),
	})
	patterns, repoRootDepth, err := ParseParentGitignores(fsys, "outside/path/to/ignore.txt")
	if err != nil {
		t.Fatalf("ParseParentGitignores(outside/path/to/ignore.txt): %v", err)
	}
	if repoRootDepth != -1 {
		t.Errorf("ParseParentGitignores(outside/path/to/ignore.txt) repoRootDepth = %d, want -1 (no repository found)", repoRootDepth)
	}
	if got := GitignoreMatch(patterns, []string{"outside", "path", "to", "ignore.txt"}, false); got {
		t.Errorf("GitignoreMatch(%v): got true, want false (outside any git repository)", patterns)
	}
}

func TestParseParentGitignoresRepositoryBoundaryIsWhereRulesStart(t *testing.T) {
	// The two halves in one tree, so that dropping every .gitignore is not a
	// passing answer: "outside" is not a repository and its .gitignore must
	// be ignored, while "outside/repo" is one and its own .gitignore must
	// still be honoured.
	fsys := buildFS(t, map[string][]byte{
		"outside/.gitignore":      []byte("ignore.txt\n"),
		"outside/repo/.git":       nil,
		"outside/repo/.gitignore": []byte("inner.txt\n"),
	})
	patterns, repoRootDepth, err := ParseParentGitignores(fsys, "outside/repo/child")
	if err != nil {
		t.Fatalf("ParseParentGitignores(outside/repo/child): %v", err)
	}
	// outside=0, repo=1; "repo" is the nearest repository root.
	if want := 1; repoRootDepth != want {
		t.Errorf("ParseParentGitignores(outside/repo/child) repoRootDepth = %d, want %d", repoRootDepth, want)
	}
	if got := GitignoreMatch(patterns, []string{"outside", "repo", "ignore.txt"}, false); got {
		t.Errorf("GitignoreMatch(ignore.txt) = true, want false: a .gitignore above the repository root must not apply")
	}
	if got := GitignoreMatch(patterns, []string{"outside", "repo", "inner.txt"}, false); !got {
		t.Errorf("GitignoreMatch(inner.txt) = false, want true: the repository's own .gitignore must still apply")
	}
}

func TestParseParentGitignoresNestedRepository(t *testing.T) {
	// nestedrepo is a git repository whose .gitignore ignores "ignore.txt".
	// nestedrepo/sub is itself a *separate* (e.g. submodule) repository, so
	// it must not inherit the outer repository's rules -- ignoring files
	// from a parent repository must not leak into a git subrepository.
	fsys := buildFS(t, map[string][]byte{
		"nestedrepo/.git":       nil,
		"nestedrepo/.gitignore": []byte("ignore.txt\n"),
		"nestedrepo/sub/.git":   nil,
	})
	patterns, repoRootDepth, err := ParseParentGitignores(fsys, "nestedrepo/sub/child")
	if err != nil {
		t.Fatalf("ParseParentGitignores(nestedrepo/sub/child): %v", err)
	}
	// The nearest repository root is "sub" itself (index 1: nestedrepo=0,
	// sub=1), not the outer "nestedrepo" repository.
	if want := 1; repoRootDepth != want {
		t.Errorf("ParseParentGitignores(nestedrepo/sub/child) repoRootDepth = %d, want %d", repoRootDepth, want)
	}
	if got := GitignoreMatch(patterns, []string{"nestedrepo", "sub", "ignore.txt"}, false); got {
		t.Errorf("GitignoreMatch(%v): got true, want false (parent repository's .gitignore must not apply inside the nested repository)", patterns)
	}
}
