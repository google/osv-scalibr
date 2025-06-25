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
// and the scan root, excluding the current directory.
func ParseParentGitignores(fs scalibrfs.FS, dirPath string) ([]GitignorePattern, error) {
	filePath := ""
	result := []GitignorePattern{}
	components := strings.Split(dirPath, "/")
	for _, dir := range components[:len(components)-1] {
		filePath += dir + "/"
		gitignores, err := ParseDirForGitignore(fs, filePath)
		if err != nil {
			return nil, err
		}
		result = append(result, gitignores)
	}
	return result, nil
}
