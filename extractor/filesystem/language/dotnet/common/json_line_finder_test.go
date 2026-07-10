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

package common_test

import (
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/common"
)

func TestJSONLineFinder(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		segments []string
		wantLine int
	}{
		{
			name:     "valid path first level",
			json:     `{"foo": "bar"}`,
			segments: []string{"foo"},
			wantLine: 1,
		},
		{
			name: "nested path",
			json: `{
  "foo": {
    "bar": "baz"
  }
}`,
			segments: []string{"foo", "bar"},
			wantLine: 3,
		},
		{
			name:     "path not found",
			json:     `{"foo": "bar"}`,
			segments: []string{"invalid"},
			wantLine: 0,
		},
		{
			name:     "dot in key",
			json:     `{"foo.bar": {"baz.qux": "val"}}`,
			segments: []string{"foo.bar", "baz.qux"},
			wantLine: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finder := common.NewJSONLineFinder(tt.json)
			got := finder.LineOf(tt.segments...)
			if got != tt.wantLine {
				t.Errorf("LineOf(%v) = %d, want %d", tt.segments, got, tt.wantLine)
			}
		})
	}
}
