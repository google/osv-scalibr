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

package codecatalyst_test

import (
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/gitbasicauth/codecatalyst"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/testing/extracttest"
	codecatalystdetector "github.com/google/osv-scalibr/veles/secrets/gitbasicauth/codecatalyst"
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
		{inputPath: `C:\Users\YourUserName\AppData\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.tx`, isWindows: true, want: true},
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

func TestExtractor_Extract(t *testing.T) {
	tests := []*struct {
		Name        string
		Path        string
		WantSecrets []*inventory.Secret
		WantErr     error
	}{
		{
			Name:        "empty",
			Path:        "empty",
			WantSecrets: nil,
		},
		{
			Name: "git_credentials",
			Path: "git_credentials",
			WantSecrets: []*inventory.Secret{
				{
					Secret: codecatalystdetector.Credentials{
						FullURL: `https://user:password@git.region.codecatalyst.aws/v1/space/project/repo`,
					},
					Location: "git_credentials",
				},
			},
		},
		{
			Name: "git_config",
			Path: "git_config",
			WantSecrets: []*inventory.Secret{
				{
					Secret: codecatalystdetector.Credentials{
						FullURL: `https://user:password@git.region.codecatalyst.aws/v1/space/project/repo`,
					},
					Location: "git_config",
				},
			},
		},
		{
			Name: "history_file",
			Path: ".zsh_history",
			WantSecrets: []*inventory.Secret{
				{
					Secret: codecatalystdetector.Credentials{
						FullURL: `https://user:password@git.region.codecatalyst.aws/v1/space/project/test-repo`,
					},
					Location: ".zsh_history",
				},
			},
		},
		{
			Name:        "random_content",
			Path:        "random_content",
			WantSecrets: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := codecatalyst.New()

			inputCfg := extracttest.ScanInputMockConfig{
				Path:         tt.Path,
				FakeScanRoot: "testdata",
			}

			scanInput := extracttest.GenerateScanInputMock(t, inputCfg)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Secrets: tt.WantSecrets}
			opts := []cmp.Option{cmpopts.SortSlices(extracttest.PackageCmpLess), cmpopts.EquateEmpty()}
			if diff := cmp.Diff(wantInv, got, opts...); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.Path, diff)
			}
		})
	}
}
