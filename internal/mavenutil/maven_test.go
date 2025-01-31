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

package mavenutil

import (
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestParentPOMPath(t *testing.T) {
	input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
		Path: filepath.Join("fixtures", "my-app", "pom.xml"),
	})
	defer extracttest.CloseTestScanInput(t, input)

	tests := []struct {
		currentPath, relativePath string
		want                      string
	}{
		// fixtures
		// |- maven
		// |  |- my-app
		// |  |  |- pom.xml
		// |  |- parent
		// |  |  |- pom.xml
		// |- pom.xml
		{
			// Parent path is specified correctly.
			currentPath:  filepath.Join("fixtures", "my-app", "pom.xml"),
			relativePath: "../parent/pom.xml",
			want:         filepath.Join("fixtures", "parent", "pom.xml"),
		},
		{
			// Wrong file name is specified in relative path.
			currentPath:  filepath.Join("fixtures", "my-app", "pom.xml"),
			relativePath: "../parent/abc.xml",
			want:         "",
		},
		{
			// Wrong directory is specified in relative path.
			currentPath:  filepath.Join("fixtures", "my-app", "pom.xml"),
			relativePath: "../not-found/pom.xml",
			want:         "",
		},
		{
			// Only directory is specified.
			currentPath:  filepath.Join("fixtures", "my-app", "pom.xml"),
			relativePath: "../parent",
			want:         filepath.Join("fixtures", "parent", "pom.xml"),
		},
		{
			// Parent relative path is default to '../pom.xml'.
			currentPath:  filepath.Join("fixtures", "my-app", "pom.xml"),
			relativePath: "",
			want:         filepath.Join("fixtures", "pom.xml"),
		},
		{
			// No pom.xml is found even in the default path.
			currentPath:  filepath.Join("fixtures", "pom.xml"),
			relativePath: "",
			want:         "",
		},
	}
	for _, tt := range tests {
		got := parentPOMPath(&input, tt.currentPath, tt.relativePath)
		if got != filepath.ToSlash(tt.want) {
			t.Errorf("ParentPOMPath(%s, %s): got %s, want %s", tt.currentPath, tt.relativePath, got, tt.want)
		}
	}
}
