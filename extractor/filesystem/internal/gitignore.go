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
	"bufio"
	"os"
	"path"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

// GitignorePattern is a list of patterns found inside a .gitignore file.
type GitignorePattern gitignore.Matcher

// EmptyGitignore returns an empty matcher that doesn't match on any pattern.
func EmptyGitignore() GitignorePattern {
	return gitignore.NewMatcher(nil)
}

// GitignoreMatch returns whether the specified file path should be ignored
// according to the specified .gitignore patterns.
func GitignoreMatch(gitignores []GitignorePattern, filePath []string, isDir bool) bool {
	for _, p := range gitignores {
		if p != nil && p.Match(filePath, isDir) {
			return true
		}
	}
	return false
}

// HasGitMarker reports whether the specified directory contains a ".git"
// entry, marking it as the root of a git repository. A ".git" entry is a
// directory for a normal checkout, or a file for a submodule or a linked
// worktree -- either is treated as a repository boundary here.
func HasGitMarker(fs scalibrfs.FS, dirPath string) bool {
	dirPath = strings.TrimSuffix(dirPath, "/")
	_, err := fs.Stat(path.Join(dirPath, ".git"))
	return err == nil
}

// ParseDirForGitignore parses .gitignore patterns found in the
// specified directory.
func ParseDirForGitignore(fs scalibrfs.FS, dirPath string) (GitignorePattern, error) {
	dirPath = strings.TrimSuffix(dirPath, "/")
	filePath := path.Join(dirPath, ".gitignore")
	f, err := fs.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	ps := []gitignore.Pattern{}
	pathTokens := strings.Split(dirPath, "/")
	for scanner.Scan() {
		s := scanner.Text()
		if !strings.HasPrefix(s, "#") && len(strings.TrimSpace(s)) > 0 {
			ps = append(ps, gitignore.ParsePattern(s, pathTokens))
		}
	}
	return gitignore.NewMatcher(ps), nil
}

// ParseParentGitignores parses all .gitignore patterns between the current dir
// and the scan root, excluding the current directory. It also returns the
// depth (0-indexed, matching the returned slice) of the nearest ancestor
// directory that is itself a git repository root, or -1 if none of the
// ancestors are inside a git repository.
//
// .gitignore files found above that repository root are excluded from the
// result: gitignore rules only apply within the boundaries of their own
// repository, so a directory that isn't inside any repository must not have
// stray .gitignore files applied to it, and a nested repository (e.g. a
// submodule) must not inherit its parent repository's rules.
func ParseParentGitignores(fs scalibrfs.FS, dirPath string) ([]GitignorePattern, int, error) {
	var filePath strings.Builder
	result := []GitignorePattern{}
	components := strings.Split(dirPath, "/")
	repoRootDepth := -1
	for i, dir := range components[:len(components)-1] {
		filePath.WriteString(dir + "/")
		dirStr := filePath.String()
		if HasGitMarker(fs, dirStr) {
			repoRootDepth = i
		}
		gitignores, err := ParseDirForGitignore(fs, dirStr)
		if err != nil {
			return nil, -1, err
		}
		result = append(result, gitignores)
	}
	// Nil out any .gitignore found above the nearest repository root (or all
	// of them, if none of the ancestors are inside a repository) -- they
	// don't apply to dirPath.
	boundary := repoRootDepth
	if boundary < 0 {
		boundary = len(result)
	}
	for i := 0; i < boundary; i++ {
		result[i] = nil
	}
	return result, repoRootDepth, nil
}
