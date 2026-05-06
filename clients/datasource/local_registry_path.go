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

package datasource

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

func localRegistryPath(kind, root string, paths []string) (string, error) {
	for _, elem := range paths {
		if elem == "" || path.IsAbs(elem) || strings.Contains(elem, `\`) {
			return "", fmt.Errorf("invalid %s local registry cache path %q", kind, paths)
		}
		for _, part := range strings.Split(elem, "/") {
			if part == "" || part == "." || part == ".." {
				return "", fmt.Errorf("invalid %s local registry cache path %q", kind, paths)
			}
		}
	}

	rel := filepath.FromSlash(path.Join(paths...))
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("invalid %s local registry cache path %q", kind, paths)
	}

	filePath := filepath.Join(root, rel)
	relToRoot, err := filepath.Rel(root, filePath)
	if err != nil {
		return "", fmt.Errorf("failed to check %s local registry cache path %s: %w", kind, filePath, err)
	}
	if !filepath.IsLocal(relToRoot) {
		return "", fmt.Errorf("invalid %s local registry cache path %q", kind, paths)
	}

	return filePath, nil
}
