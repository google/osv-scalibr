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

package gitbasicauth_test

import (
	"runtime"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem/secrets/gitbasicauth/codecatalyst"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		inputPath string
		want      bool
		isWindows bool
	}{
		{inputPath: "", want: false},

		// linux
		{inputPath: `/Users/example-user/folder/.git/config`, want: true},
		{inputPath: `/Users/example-user/.git-credentials`, want: true},
		{inputPath: `/Users/example-user/.zsh_history`, want: true},
		{inputPath: `/Users/example-user/bad/path`, want: false},

		// windows
		{inputPath: `C:\Users\USERNAME\folder\.git\config`, isWindows: true, want: true},
		{inputPath: `C:\Users\YourUserName\.git-credentials`, isWindows: true, want: true},
		{inputPath: `C:\Users\USERNAME\another\bad\path`, isWindows: true, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			if tt.isWindows && runtime.GOOS != "windows" {
				t.Skipf("Skipping test %q for %q", t.Name(), runtime.GOOS)
			}
			e := codecatalyst.New()
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}
