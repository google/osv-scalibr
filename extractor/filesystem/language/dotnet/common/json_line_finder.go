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

package common

import (
	"strings"

	"github.com/tidwall/gjson"
)

// JSONLineFinder finds line numbers of JSON paths.
type JSONLineFinder struct {
	json         string
	offsetFinder *OffsetFinder
}

// NewJSONLineFinder creates a new JSONLineFinder.
func NewJSONLineFinder(json string) *JSONLineFinder {
	return &JSONLineFinder{
		json:         json,
		offsetFinder: NewOffsetFinder([]byte(json)),
	}
}

// LineOf returns the line number of the JSON path formed by joining the given segments.
// If the path is not found or cannot be parsed, it returns 0.
func (f *JSONLineFinder) LineOf(segments ...string) int {
	var escaped []string
	for _, s := range segments {
		escaped = append(escaped, gjson.Escape(s))
	}
	path := strings.Join(escaped, ".")
	res := gjson.Get(f.json, path)
	if !res.Exists() {
		return 0
	}
	return f.offsetFinder.LineOfOffset(int64(res.Index))
}
