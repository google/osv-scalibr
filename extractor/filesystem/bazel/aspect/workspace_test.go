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

package aspect

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("MkdirAll(): %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
}

func TestCoveringWorkspace(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "MODULE.bazel"), "")
	writeTestFile(t, filepath.Join(root, ".bazelignore"), "ignored\npartial/sub\n")
	writeTestFile(t, filepath.Join(root, "a", "MODULE.bazel"), "")
	writeTestFile(t, filepath.Join(root, "a", "b", "WORKSPACE.bazel"), "")
	writeTestFile(t, filepath.Join(root, "ignored", "MODULE.bazel"), "")
	writeTestFile(t, filepath.Join(root, "ignored", "c", "MODULE.bazel"), "")
	writeTestFile(t, filepath.Join(root, "partial", "MODULE.bazel"), "")
	writeTestFile(t, filepath.Join(root, "no_ws", "d", "MODULE.bazel"), "")

	tests := []struct {
		ws   string
		want string
	}{
		{ws: ".", want: ""},
		{ws: "a", want: "."},
		// Covered by the root workspace through "a".
		{ws: filepath.Join("a", "b"), want: "."},
		{ws: "ignored", want: ""},
		{ws: filepath.Join("ignored", "c"), want: "ignored"},
		// The root workspace ignores part of it, so it needs its own build.
		{ws: "partial", want: ""},
		{ws: filepath.Join("no_ws", "d"), want: "."},
	}
	for _, tt := range tests {
		t.Run(tt.ws, func(t *testing.T) {
			got := coveringWorkspace(root, filepath.Join(root, tt.ws))
			want := ""
			if tt.want != "" {
				want = filepath.Join(root, tt.want)
			}
			if got != want {
				t.Errorf("coveringWorkspace(%q) = %q, want %q", tt.ws, got, want)
			}
		})
	}

	// Workspaces outside the scan root aren't considered.
	sub := filepath.Join(root, "a")
	if got := coveringWorkspace(sub, filepath.Join(sub, "b")); got != sub {
		t.Errorf("coveringWorkspace() with scan root %q = %q, want %q", sub, got, sub)
	}
	if got := coveringWorkspace(sub, sub); got != "" {
		t.Errorf("coveringWorkspace() of the scan root = %q, want \"\"", got)
	}
}

func TestIsTopLevelWorkspace(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "MODULE.bazel"), "")
	writeTestFile(t, filepath.Join(root, "a", "MODULE.bazel"), "")

	if !isTopLevelWorkspace(root, root) {
		t.Errorf("isTopLevelWorkspace(root) = false, want true")
	}
	if isTopLevelWorkspace(root, filepath.Join(root, "a")) {
		t.Errorf("isTopLevelWorkspace(a) = true, want false")
	}
	if !isTopLevelWorkspace(filepath.Join(root, "a"), filepath.Join(root, "a")) {
		t.Errorf("isTopLevelWorkspace(a) with scan root a = false, want true")
	}
}

func TestIsWithin(t *testing.T) {
	tests := []struct {
		dir, path string
		want      bool
	}{
		{dir: "/a", path: "/a", want: true},
		{dir: "/a", path: "/a/b", want: true},
		{dir: "/a", path: "/ab", want: false},
		{dir: "/a/b", path: "/a", want: false},
		{dir: "/a", path: "/a/..b", want: true},
	}
	for _, tt := range tests {
		if got := isWithin(filepath.FromSlash(tt.dir), filepath.FromSlash(tt.path)); got != tt.want {
			t.Errorf("isWithin(%q, %q) = %v, want %v", tt.dir, tt.path, got, tt.want)
		}
	}
}
