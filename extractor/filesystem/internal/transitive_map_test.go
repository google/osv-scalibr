// Copyright 2024 Google LLC
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
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestBuildTransitiveMaps(t *testing.T) {
	tests := []struct {
		name  string
		input map[string]int
		want  map[string]int
	}{
		{
			name:  "single",
			input: map[string]int{"a": 1, filepath.FromSlash("a/b"): 2},
			want:  map[string]int{".": 3, "a": 2},
		},
		{
			name:  "double",
			input: map[string]int{"a": 1, filepath.FromSlash("a/b"): 2, filepath.FromSlash("a/b/c"): 3},
			want:  map[string]int{".": 6, "a": 5, filepath.FromSlash("a/b"): 3},
		},
		{
			name:  "only in leaf directory",
			input: map[string]int{filepath.FromSlash("a/b/c"): 3},
			want:  map[string]int{".": 3, "a": 3, filepath.FromSlash("a/b"): 3},
		},
		{
			name:  "2 leaf directories",
			input: map[string]int{filepath.FromSlash("a/b/c"): 3, filepath.FromSlash("a/b/d"): 2},
			want:  map[string]int{".": 5, "a": 5, filepath.FromSlash("a/b"): 5},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := BuildTransitiveMaps(test.input)
			if diff := cmp.Diff(got, test.want); diff != "" {
				t.Errorf("buildTransitiveMaps(%v) = %v, want %v", test.input, got, test.want)
			}
		})
	}
}
