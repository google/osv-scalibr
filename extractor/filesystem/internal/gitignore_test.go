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

package internal

import (
	"testing"

	scalibrfs "github.com/google/osv-scalibr/fs"
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
			path:      []string{"testdata", "path", "to", "file.py"},
			wantMatch: false,
		},
		{
			name:      "Match_pattern_from_parent_dir",
			path:      []string{"testdata", "path", "to", "ignore.txt"},
			wantMatch: true,
		},
		{
			name:      "Match_pattern_from_child_dir",
			path:      []string{"testdata", "subdir", "path", "to", "ignore2.txt"},
			wantMatch: true,
		},
	}

	patterns, err := ParseParentGitignores(scalibrfs.DirFS("."), "testdata/subdir")
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
