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

import "path/filepath"

// ParentDir returns the parent dir up to n dirs deep.
// If the path is below n dirs, the function returns path.
// This function assumes no leading `/` or drive letter.
func ParentDir(path string, n int) string {
	for i, c := range path {
		if c == filepath.Separator {
			n--
			if n == 0 {
				return path[:i]
			}
		}
	}
	return path
}
