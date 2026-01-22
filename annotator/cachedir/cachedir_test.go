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

package cachedir_test

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/annotator/cachedir"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
)

func TestIsInsideCacheDir(t *testing.T) {
	// Define test cases with different platform-specific paths
	testCases := []struct {
		inputPath           string
		separator           rune // defaulting to '/'
		wantCacheAnnotation bool
	}{
		// Linux/Unix
		{inputPath: "/tmp/somefile", wantCacheAnnotation: true},
		{inputPath: "/var/cache/apt/archives", wantCacheAnnotation: true},
		{inputPath: "/home/user/.local/share/Trash/files/file.txt", wantCacheAnnotation: true},
		{inputPath: "/home/user/.cache/thumbnails", wantCacheAnnotation: true},
		{inputPath: "/root/.cache/pip", wantCacheAnnotation: true},
		{inputPath: "/home/user/projects/code", wantCacheAnnotation: false},

		// macOS
		{inputPath: "/Users/username/Library/Caches/com.apple.Safari", wantCacheAnnotation: true},
		{inputPath: "/private/tmp/mytmpfile", wantCacheAnnotation: true},
		{inputPath: "/System/Volumes/Data/private/var/tmp/file", wantCacheAnnotation: true},
		{inputPath: "/System/Volumes/Data/private/tmp/file", wantCacheAnnotation: true},
		{inputPath: "/Users/username/Documents", wantCacheAnnotation: false},

		// Windows
		{inputPath: "C:\\Users\\testuser\\AppData\\Local\\Temp\\tempfile.txt", separator: '\\', wantCacheAnnotation: true},
		{inputPath: "C:\\Windows\\Temp\\log.txt", separator: '\\', wantCacheAnnotation: true},
		{inputPath: "C:\\Program Files\\MyApp", separator: '\\', wantCacheAnnotation: false},

		// Edge cases
		{inputPath: "", wantCacheAnnotation: false},
		{inputPath: "some/relative/path", wantCacheAnnotation: false},
	}

	for _, tt := range testCases {
		t.Run(tt.inputPath, func(t *testing.T) {
			if tt.separator == 0 {
				tt.separator = '/'
			}

			if os.PathSeparator != tt.separator {
				t.Skipf("Skipping IsInsideCacheDir(%q)", tt.inputPath)
			}

			inv := &inventory.Inventory{
				Packages: []*extractor.Package{&extractor.Package{
					Locations: []string{tt.inputPath},
				}},
			}
			if err := cachedir.New().Annotate(t.Context(), nil, inv); err != nil {
				t.Errorf("Annotate(%v): %v", inv, err)
			}
			var want []*vex.PackageExploitabilitySignal
			if tt.wantCacheAnnotation {
				want = []*vex.PackageExploitabilitySignal{&vex.PackageExploitabilitySignal{
					Plugin:          cachedir.Name,
					Justification:   vex.ComponentNotPresent,
					MatchesAllVulns: true,
				}}
			}

			got := inv.Packages[0].ExploitabilitySignals
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Annotate(%v) (-want +got):\n%s", inv, diff)
			}
		})
	}
}
