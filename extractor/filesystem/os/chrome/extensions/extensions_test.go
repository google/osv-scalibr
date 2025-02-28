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

package extensions_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/os/chrome/extensions"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			inputPath: "",
			want:      false,
		},
		// todo : this
	}
	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			e := extensions.Extractor{}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.json",
			},
			WantErr: extracttest.ContainsErrStr{Str: "bad format"},
		},
		{
			Name: "no locale specified",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/jkbfewkjnflewmfpewmgpewknfojewnf/1.2.85/manifest.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:    "jkbfewkjnflewmfpewmgpewknfojewnf",
					Version: "1.2.85",
					Metadata: extensions.Metadata{
						Description:     "A decentralized wallet for blockchain transactions.",
						HostPermissions: []string{"file://*/*", "http://*/*", "https://*/*"},
						ManifestVersion: 3,
						Name:            "CryptoX Blockchain Wallet",
						Permissions:     []string{"storage", "tabs", "alarms"},
						UpdateURL:       "https://clients2.google.com/service/update2/crx",
						Version:         "1.2.85",
					},
				},
			},
		},
		{
			Name: "locale specified without message",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid-name/1.89.1/manifest.json",
			},
			WantErr: extracttest.ContainsErrStr{Str: "could not extract locale info from"},
		},
		{
			Name: "locale specified",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/ghbmnnjooekpmoecnnnilnnbdlolhkhi/1.89.1/manifest.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:    "ghbmnnjooekpmoecnnnilnnbdlolhkhi",
					Version: "1.89.1",
					Metadata: extensions.Metadata{
						AuthorEmail:          "docs-hosted-app-own@google.com",
						Description:          "Edit, create, and view your documents, spreadsheets, and presentations — all without internet access.",
						HostPermissions:      []string{"https://docs.google.com/*", "https://drive.google.com/*"},
						ManifestVersion:      3,
						MinimumChromeVersion: "88",
						Name:                 "Google Docs Offline",
						Permissions:          []string{"alarms", "storage", "unlimitedStorage", "offscreen"},
						UpdateURL:            "https://clients2.google.com/service/update2/crx",
						Version:              "1.89.1",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := extensions.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(context.Background(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			if diff := cmp.Diff(tt.WantInventory, got, cmpopts.SortSlices(extracttest.InventoryCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
