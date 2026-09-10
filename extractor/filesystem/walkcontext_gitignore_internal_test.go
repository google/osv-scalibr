// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package filesystem

import (
	"io/fs"
	"testing"
)

type stubDirEntry struct {
	name  string
	isDir bool
}

func (e stubDirEntry) Name() string { return e.name }
func (e stubDirEntry) IsDir() bool  { return e.isDir }
func (e stubDirEntry) Type() fs.FileMode {
	if e.isDir {
		return fs.ModeDir
	}
	return 0
}
func (e stubDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

// TestPostHandleFileOnlyPopsRepoRootDepthForDirectories pins down the
// push/pop symmetry of repoRootDepthStack. Only directories push onto it, in
// handleFile, so only directories may pop from it. Popping on a file restores
// the enclosing directory's value while that directory is still being walked,
// and every sibling directory visited afterwards then runs with a stale
// repository-root depth -- with -1 meaning "not inside a repository", their
// .gitignore files are not read at all.
//
// The walk uses readdir order, so whether a file is seen before a sibling
// directory depends on the filesystem, which makes the effect invisible on
// some machines and reproducible on others. Asserting on the bookkeeping
// directly keeps it deterministic.
func TestPostHandleFileOnlyPopsRepoRootDepthForDirectories(t *testing.T) {
	wc := &walkContext{
		useGitignore:       true,
		repoRootDepth:      3,
		repoRootDepthStack: []int{7},
	}

	wc.postHandleFile("dir/file.txt", stubDirEntry{name: "file.txt"})
	if got, want := wc.repoRootDepth, 3; got != want {
		t.Errorf("after a file: repoRootDepth = %d, want %d (a file must not restore the enclosing directory's depth)", got, want)
	}
	if got, want := len(wc.repoRootDepthStack), 1; got != want {
		t.Errorf("after a file: len(repoRootDepthStack) = %d, want %d", got, want)
	}

	wc.postHandleFile("dir", stubDirEntry{name: "dir", isDir: true})
	if got, want := wc.repoRootDepth, 7; got != want {
		t.Errorf("after the directory: repoRootDepth = %d, want %d (leaving a directory must restore the saved depth)", got, want)
	}
	if got, want := len(wc.repoRootDepthStack), 0; got != want {
		t.Errorf("after the directory: len(repoRootDepthStack) = %d, want %d", got, want)
	}
}
