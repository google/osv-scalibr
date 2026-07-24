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

func TestOffsetFinder(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		offset   int64
		wantLine int
	}{
		{
			name:     "first line start",
			content:  "line 1\nline 2\nline 3",
			offset:   0,
			wantLine: 1,
		},
		{
			name:     "first line middle",
			content:  "line 1\nline 2\nline 3",
			offset:   3,
			wantLine: 1,
		},
		{
			name:     "second line start",
			content:  "line 1\nline 2\nline 3",
			offset:   7,
			wantLine: 2,
		},
		{
			name:     "second line middle",
			content:  "line 1\nline 2\nline 3",
			offset:   10,
			wantLine: 2,
		},
		{
			name:     "third line start",
			content:  "line 1\nline 2\nline 3",
			offset:   14,
			wantLine: 3,
		},
		{
			name:     "offset beyond end of content",
			content:  "line 1\nline 2\nline 3",
			offset:   100,
			wantLine: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finder := common.NewOffsetFinder([]byte(tt.content))
			got := finder.LineOfOffset(tt.offset)
			if got != tt.wantLine {
				t.Errorf("LineOfOffset(%d) = %d, want %d", tt.offset, got, tt.wantLine)
			}
		})
	}
}
