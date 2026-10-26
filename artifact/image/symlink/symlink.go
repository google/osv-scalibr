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

// Package symlink provides symlink-related util functions for container extraction.
package symlink

import (
	"path"
	"strings"

	"github.com/google/uuid"
)

// TargetOutsideRoot checks if the target of a symlink points outside of the root directory of that
// symlink's path.
// For example, if a symlink with path `a/symlink.txt“ points to “../../file.text“, then
// this function would return true because the target file is outside of the root directory.
func TargetOutsideRoot(symlinkPath, target string) bool {
	// Create a marker directory as root to check if the target path is outside of the root directory.
	markerDir := uuid.New().String()
	if path.IsAbs(target) {
		// Absolute paths may still point outside of the root directory.
		// e.g. "/../file.txt"
		markerTarget := path.Join(markerDir, target)
		return !strings.Contains(markerTarget, markerDir)
	}

	markerTargetAbs := path.Join(markerDir, path.Dir(symlinkPath), target)
	return !strings.Contains(markerTargetAbs, markerDir)
}
