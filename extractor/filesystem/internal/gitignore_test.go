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
	"testing"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/google/osv-scalibr/testing/fakefs"
)

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

	pattern, err := ParseDirForGitignore(fakefs.DirFS(t, fakefs.CopyTestData(t, ".")), "testdata")
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
	_, err := ParseDirForGitignore(fakefs.DirFS(t, fakefs.CopyTestData(t, ".")), "testdata/nonexistent")
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
			path:      []string{"testdata", "path", "to", "file.py"},
			wantMatch: false,
		},
		{
			name:      "Match_pattern_from_parent_dir",
			path:      []string{"testdata", "path", "to", "ignore.txt"},
			wantMatch: true,
		},
		{
			name:      "Dont_match_pattern_from_child_dir",
			path:      []string{"testdata", "subdir", "path", "to", "ignore2.txt"},
			wantMatch: false,
		},
	}

	patterns, err := ParseParentGitignores(fakefs.DirFS(t, fakefs.CopyTestData(t, ".")), "testdata/subdir")
	if err != nil {
		t.Fatalf("ParseParentGitignores(testdata): %v", err)
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

func TestChildGitignoreNegationOverridesParent(t *testing.T) {
	parentPatterns := GitignorePattern{
		gitignore.ParsePattern("*.txt", nil),
		gitignore.ParsePattern("build/", nil),
	}
	childPatterns := GitignorePattern{
		gitignore.ParsePattern("!requirements.txt", []string{"app"}),
	}

	gitignores := []GitignorePattern{parentPatterns, childPatterns}

	tests := []struct {
		name      string
		path      []string
		wantMatch bool
	}{
		{
			name:      "child_negation_reincludes_file",
			path:      []string{"app", "requirements.txt"},
			wantMatch: false,
		},
		{
			name:      "child_other_file_still_ignored_by_parent",
			path:      []string{"app", "other.txt"},
			wantMatch: true,
		},
		{
			name:      "sibling_file_without_override_ignored_by_parent",
			path:      []string{"hidden", "requirements.txt"},
			wantMatch: true,
		},
		{
			name:      "unmatched_file_not_ignored",
			path:      []string{"app", "main.py"},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GitignoreMatch(gitignores, tt.path, false)
			if got != tt.wantMatch {
				t.Errorf("GitignoreMatch(%v, %v): got %v, want %v", gitignores, tt.path, got, tt.wantMatch)
			}
		})
	}
}
