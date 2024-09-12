// Copyright 2024 Google LLC
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

package require_test

import (
	"testing"

	"github.com/google/osv-scalibr/artifact/image/require"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name     string
		requirer require.FileRequirer
		path     string
		want     bool
	}{{
		name:     "always require file",
		requirer: &require.FileRequirerAll{},
		path:     "some/file.txt",
		want:     true,
	}, {
		name:     "never require file",
		requirer: &require.FileRequirerNone{},
		path:     "some/file.txt",
		want:     false,
	}, {
		name:     "require specific file",
		requirer: require.NewFileRequirerPaths([]string{"some/file.txt"}),
		path:     "some/file.txt",
		want:     true,
	}, {
		name:     "require specific file",
		requirer: require.NewFileRequirerPaths([]string{"some/file.txt"}),
		path:     "another/file.txt",
		want:     false,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.requirer.FileRequired(tc.path, nil)
			if got != tc.want {
				t.Errorf("FileRequired(%q, nil) = %v, want: %v", tc.path, got, tc.want)
			}
		})
	}
}
