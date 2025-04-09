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

	"github.com/google/osv-scalibr/extractor"
)

// Annotate adds annotations to the inventory
func Annotate(pkgs []*extractor.Package) {
	for _, pkg := range pkgs {
		for _, loc := range pkg.Locations {
			if IsInsideCacheDir(loc) {
				pkg.Annotations = append(pkg.Annotations, extractor.InsideCacheDir)
			}
		}
	}
}

// Precompile regex patterns to match cache directories
var cacheDirPatterns = []*regexp.Regexp{
	// Linux/Unix-like systems
	regexp.MustCompile(`^/tmp`),                            // Common temporary storage location
	regexp.MustCompile(`^/var/cache`),                      // Common system cache directory
	regexp.MustCompile(`^/home/[^/]+/\.local/share/Trash`), // User-specific cache directory
	regexp.MustCompile(`^/home/[^/]+/\.cache`),             // User-specific cache directory

	// macOS
	regexp.MustCompile(`^/Users/[^/]+/Library/Caches`),  // User cache directory
	regexp.MustCompile(`^/private/tmp`),                 // System temporary files location
	regexp.MustCompile(`^/System/Volumes/Data/var/tmp`), // System temporary files location

	// Windows
	regexp.MustCompile(`^C\:/Users/[^/]+/AppData/Local/Temp`), // %LOCALAPPDATA%\Temp on Windows
	regexp.MustCompile(`^C\:/Windows/Temp`),                   // System temporary files
}

// IsInsideCacheDir checks if the given path is inside a cache directory.
func IsInsideCacheDir(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	absPath = filepath.ToSlash(absPath)

	// Check if the absolute path matches any of the known cache directory patterns
	for _, pattern := range cacheDirPatterns {
		if pattern.MatchString(absPath) {
			return true
		}
	}
	return false
}
