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

package plugger

import (
	"go/ast"
	"slices"
	"strings"
)

func hasNoLint(commentGroup *ast.CommentGroup, name string) bool {
	if commentGroup == nil {
		return false
	}
	for _, comment := range commentGroup.List {
		text := comment.Text
		linters, ok := strings.CutPrefix(text, "//nolint:")
		if !ok {
			continue
		}

		// remove comment after //nolint, ex:
		//
		//	//nolint:plugger //something
		linters, _, _ = strings.Cut(linters, " ")

		// return true if one of the comma separated linter is plugger
		if slices.Contains(strings.Split(linters, ","), name) {
			return true
		}
	}
	return false
}
