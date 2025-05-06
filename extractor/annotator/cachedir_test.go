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

package annotator

import (
	"os"
	"testing"
)

func TestIsInsideCacheDir(t *testing.T) {
	// Define test cases with different platform-specific paths
	testCases := []struct {
		inputPath string
		separator rune // defaulting to '/'
		want      bool
	}{
		// Linux/Unix
		{inputPath: "/tmp/somefile", want: true},
		{inputPath: "/var/cache/apt/archives", want: true},
		{inputPath: "/home/user/.local/share/Trash/files/file.txt", want: true},
		{inputPath: "/home/user/.cache/thumbnails", want: true},
		{inputPath: "/home/user/projects/code", want: false},

		// macOS
		{inputPath: "/Users/username/Library/Caches/com.apple.Safari", want: true},
		{inputPath: "/private/tmp/mytmpfile", want: true},
		{inputPath: "/System/Volumes/Data/private/var/tmp/file", want: true},
		{inputPath: "/System/Volumes/Data/private/tmp/file", want: true},
		{inputPath: "/Users/username/Documents", want: false},

		// Windows
		{inputPath: "C:\\Users\\testuser\\AppData\\Local\\Temp\\tempfile.txt", separator: '\\', want: true},
		{inputPath: "C:\\Windows\\Temp\\log.txt", separator: '\\', want: true},
		{inputPath: "C:\\Program Files\\MyApp", separator: '\\', want: false},

		// Edge cases
		{inputPath: "", want: false},
		{inputPath: "some/relative/path", want: false},
	}

	for _, tt := range testCases {
		t.Run(tt.inputPath, func(t *testing.T) {
			if tt.separator == 0 {
				tt.separator = '/'
			}

			if os.PathSeparator != tt.separator {
				t.Skipf("Skipping IsInsideCacheDir(%q)", tt.inputPath)
			}
			got := IsInsideCacheDir(tt.inputPath)
			if got != tt.want {
				t.Errorf("IsInsideCacheDir(%q) = %v; want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}
