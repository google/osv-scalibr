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
	"fmt"
	"path/filepath"
	"testing"
)

func TestParentDir(t *testing.T) {
	tests := []struct {
		path string
		n    int
		want string
	}{
		{path: ".", n: 3, want: "."},
		{path: "a/b/c/d", n: 3, want: "a/b/c"},
		{path: "a/b/c/d", n: 1, want: "a"},
		{path: "a/b", n: 3, want: "a/b"},
		{path: "a", n: 3, want: "a"},
		{path: "asdf/yolo/foo/test/bla", n: 3, want: "asdf/yolo/foo"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("ParentDir(%q, %d), want %q", test.path, test.n, test.want), func(t *testing.T) {
			got := ParentDir(filepath.FromSlash(test.path), test.n)
			if filepath.ToSlash(got) != test.want {
				t.Errorf("ParentDir(%q, %d) = %q, want %q", test.path, test.n, got, test.want)
			}
		})
	}
}
