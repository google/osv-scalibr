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

package awsaccesskey_test

import (
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/awsaccesskey"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/testing/extracttest"
	awsaccesskeydetector "github.com/google/osv-scalibr/veles/secrets/awsaccesskey"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		inputPath string
		want      bool
		isWindows bool
	}{
		{inputPath: "", want: false},

		// linux
		{inputPath: `/Users/example-user/.aws/credentials`, want: true},
		{inputPath: `/Users/example-user/bad/path`, want: false},

		// windows
		{inputPath: `C:\Users\USERNAME\.aws\credentials`, isWindows: true, want: true},
		{inputPath: `C:\Users\USERNAME\another\bad\path`, isWindows: true, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			if tt.isWindows && runtime.GOOS != "windows" {
				t.Skipf("Skipping test %q for %q", t.Name(), runtime.GOOS)
			}
			e := awsaccesskey.New()
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
			Name: "aws_credentials",
			Path: "aws_credentials",
			WantSecrets: []*inventory.Secret{
				{
					Secret: awsaccesskeydetector.Credentials{
						AccessID: "AIKA1984R439T439HTH4",
						Secret:   "32r923jr023rk320rk2a3rkB34tj340r32Ckt433",
					},
					Location: "aws_credentials",
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
			extr := awsaccesskey.New()

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
