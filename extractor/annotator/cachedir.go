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
)

// patterns to match cache directories
var cacheDirPatterns = []*regexp.Regexp{
	// Linux/Unix-like systems
	regexp.MustCompile(`^/?tmp/`),
	regexp.MustCompile(`^/?home/[^/]+/\.local/share/Trash/`),
	regexp.MustCompile(`^/?home/[^/]+/\.cache/`),
	regexp.MustCompile(`^/?var/cache/`),

	// macOS
	regexp.MustCompile(`^/?private/tmp/`),
	regexp.MustCompile(`^/?System/Volumes/Data/private/var/tmp/`),
	regexp.MustCompile(`^/?System/Volumes/Data/private/tmp/`),
	regexp.MustCompile(`^/?Users/[^/]+/Library/Caches/`),

	// Windows
	regexp.MustCompile(`(C:/)?Users/[^/]+/AppData/Local/Temp/`),
	regexp.MustCompile(`(C:/)?Windows/Temp/`),
}

// IsInsideCacheDir checks if the given path is inside a cache directory.
func IsInsideCacheDir(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	absPath = filepath.ToSlash(absPath)

	// Check if the absolute path matches any of the known cache directory patterns
	for _, r := range cacheDirPatterns {
		if r.MatchString(absPath) {
			return true
		}
	}
	return false
}
