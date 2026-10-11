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
	"strings"
)

// workspaceMarkers are the files that make a directory the root of a Bazel workspace.
var workspaceMarkers = []string{"WORKSPACE", "WORKSPACE.bazel", "MODULE.bazel"}

// isBazelWorkspace checks if the given path contains a Bazel workspace indicator.
func isBazelWorkspace(path string) bool {
	for _, marker := range workspaceMarkers {
		if _, err := os.Stat(filepath.Join(path, marker)); err == nil {
			return true
		}
	}
	return false
}

// coveringWorkspace returns the enclosing workspace (inside scanRoot) whose bazel invocation
// already builds the workspace at ws, or "" if ws needs its own invocation.
//
// Bazel treats a nested directory containing a MODULE.bazel or WORKSPACE file as ordinary
// packages of the enclosing workspace, unless the enclosing workspace's .bazelignore excludes it.
// Nested workspaces that are excluded (fully or partially) are independent and are scanned with
// their own invocation. The result doesn't depend on the order in which workspaces are found.
func coveringWorkspace(scanRoot, ws string) string {
	for dir := filepath.Dir(ws); isWithin(scanRoot, dir); dir = filepath.Dir(dir) {
		if isBazelWorkspace(dir) && coveringWorkspace(scanRoot, dir) == "" {
			// dir gets its own bazel invocation, which builds ws unless dir excludes it.
			if ignoresPartOf(dir, ws) {
				return ""
			}
			return dir
		}
		// dir is not a workspace, or its contents are built by a workspace further up.
		if parent := filepath.Dir(dir); parent == dir {
			break
		}
	}
	return ""
}

// isTopLevelWorkspace reports whether no workspace encloses ws inside scanRoot.
func isTopLevelWorkspace(scanRoot, ws string) bool {
	for dir := filepath.Dir(ws); isWithin(scanRoot, dir); dir = filepath.Dir(dir) {
		if isBazelWorkspace(dir) {
			return false
		}
		if parent := filepath.Dir(dir); parent == dir {
			break
		}
	}
	return true
}

// ignoresPartOf reports whether the .bazelignore of the workspace at ws excludes dir, one of its
// parents, or anything inside it.
func ignoresPartOf(ws, dir string) bool {
	for _, ignored := range bazelIgnoreEntries(ws) {
		if isWithin(ignored, dir) || isWithin(dir, ignored) {
			return true
		}
	}
	return false
}

// bazelIgnoreEntries returns the directories listed in the .bazelignore of the workspace at ws, as
// absolute paths.
func bazelIgnoreEntries(ws string) []string {
	data, err := os.ReadFile(filepath.Join(ws, ".bazelignore"))
	if err != nil {
		return nil
	}
	var entries []string
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, filepath.Join(ws, filepath.FromSlash(line)))
	}
	return entries
}

// isWithin reports whether path is dir or is inside dir.
func isWithin(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
