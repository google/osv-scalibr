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

// Package gitbasicauth contains common logic for git basic auth filesystem extractors.
package gitbasicauth

import (
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
)

// FileRequired reports whether the plugin should scan the given file.
//
// The history.txt file is intentionally excluded because it is already
// processed by the main secrets extractor.
func FileRequired(api filesystem.FileAPI) bool {
	path := filepath.ToSlash(api.Path())
	return strings.HasSuffix(path, ".git/config") ||
		strings.HasSuffix(path, ".git-credentials") ||
		strings.HasSuffix(path, "_history")
}
