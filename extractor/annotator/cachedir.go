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

package annotator

import (
	"path/filepath"
	"regexp"
	"strings"
)

type matcher func(string) bool

var (
	linuxTrashPattern = regexp.MustCompile(`home/[^/]+/\.local/share/Trash/`)
	linuxCachePattern = regexp.MustCompile(`home/[^/]+/\.cache/`)
	macosCachePattern = regexp.MustCompile(`Users/[^/]+/Library/Caches/`)
	windowsTmpPattern = regexp.MustCompile(`Users/[^/]+/AppData/Local/Temp/`)
)

// patterns to match cache directories
var cacheDirMatchers = []matcher{
	// Linux/Unix-like systems
	func(s string) bool { return strings.Contains(s, "tmp/") },
	func(s string) bool { return strings.Contains(s, "var/cache/") },
	linuxTrashPattern.MatchString,
	linuxCachePattern.MatchString,

	// macOS
	macosCachePattern.MatchString,
	func(s string) bool { return strings.Contains(s, "private/tmp/") },
	func(s string) bool { return strings.Contains(s, "System/Volumes/Data/var/tmp/") },

	// Windows
	windowsTmpPattern.MatchString,
	func(s string) bool { return strings.Contains(s, "Windows/Temp/") },
}

// IsInsideCacheDir checks if the given path is inside a cache directory.
func IsInsideCacheDir(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	absPath = filepath.ToSlash(absPath)

	// Check if the absolute path matches any of the known cache directory patterns
	for _, match := range cacheDirMatchers {
		if match(absPath) {
			return true
		}
	}
	return false
}
