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

package gemfilelock_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		inputPath string
		want      bool
	}{
		{
			inputPath: "",
			want:      false,
		},
		{
			inputPath: "Gemfile.lock",
			want:      true,
		},
		{
			inputPath: "path/to/my/Gemfile.lock",
			want:      true,
		},
		{
			inputPath: "path/to/my/Gemfile.lock/file",
			want:      false,
		},
		{
			inputPath: "path/to/my/Gemfile.lock.file",
			want:      false,
		},
		{
			inputPath: "path.to.my.Gemfile.lock",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			e := gemfilelock.Extractor{}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "no spec section",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-spec-section.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "no gem section",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-gem-section.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "no gems",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-gems.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "invalid spec",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one gem",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-gem.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "ast",
					Version:   "2.4.2",
					Locations: []string{"testdata/one-gem.lock"},
				},
			},
		},
		{
			Name: "trailing source section ",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/source-section-at-end.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "ast",
					Version:   "2.4.2",
					Locations: []string{"testdata/source-section-at-end.lock"},
				},
			},
		},
		{
			Name: "some gems",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/some-gems.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "coderay",
					Version:   "1.1.3",
					Locations: []string{"testdata/some-gems.lock"},
				},
				{
					Name:      "method_source",
					Version:   "1.0.0",
					Locations: []string{"testdata/some-gems.lock"},
				},
				{
					Name:      "pry",
					Version:   "0.14.1",
					Locations: []string{"testdata/some-gems.lock"},
				},
			},
		},
		{
			Name: "multiple gems",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple-gems.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "bundler-audit",
					Version:   "0.9.0.1",
					Locations: []string{"testdata/multiple-gems.lock"},
				},
				{
					Name:      "coderay",
					Version:   "1.1.3",
					Locations: []string{"testdata/multiple-gems.lock"},
				},
				{
					Name:      "dotenv",
					Version:   "2.7.6",
					Locations: []string{"testdata/multiple-gems.lock"},
				},
				{
					Name:      "method_source",
					Version:   "1.0.0",
					Locations: []string{"testdata/multiple-gems.lock"},
				},
				{
					Name:      "pry",
					Version:   "0.14.1",
					Locations: []string{"testdata/multiple-gems.lock"},
				},
				{
					Name:      "thor",
					Version:   "1.2.1",
					Locations: []string{"testdata/multiple-gems.lock"},
				},
			},
		},
		{
			Name: "rails",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/rails.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "actioncable",
					Version:   "7.0.2.2",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "actionmailbox",
					Version:   "7.0.2.2",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "actionmailer",
					Version:   "7.0.2.2",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "actionpack",
					Version:   "7.0.2.2",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "actiontext",
					Version:   "7.0.2.2",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "actionview",
					Version:   "7.0.2.2",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "activejob",
					Version:   "7.0.2.2",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "activemodel",
					Version:   "7.0.2.2",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "activerecord",
					Version:   "7.0.2.2",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "activestorage",
					Version:   "7.0.2.2",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "activesupport",
					Version:   "7.0.2.2",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "builder",
					Version:   "3.2.4",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "concurrent-ruby",
					Version:   "1.1.9",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "crass",
					Version:   "1.0.6",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "digest",
					Version:   "3.1.0",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "erubi",
					Version:   "1.10.0",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "globalid",
					Version:   "1.0.0",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "i18n",
					Version:   "1.10.0",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "io-wait",
					Version:   "0.2.1",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "loofah",
					Version:   "2.14.0",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "mail",
					Version:   "2.7.1",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "marcel",
					Version:   "1.0.2",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "method_source",
					Version:   "1.0.0",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "mini_mime",
					Version:   "1.1.2",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "minitest",
					Version:   "5.15.0",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "net-imap",
					Version:   "0.2.3",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "net-pop",
					Version:   "0.1.1",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "net-protocol",
					Version:   "0.1.2",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "net-smtp",
					Version:   "0.3.1",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "nio4r",
					Version:   "2.5.8",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "racc",
					Version:   "1.6.0",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "rack",
					Version:   "2.2.3",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "rack-test",
					Version:   "1.1.0",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "rails",
					Version:   "7.0.2.2",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "rails-dom-testing",
					Version:   "2.0.3",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "rails-html-sanitizer",
					Version:   "1.4.2",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "railties",
					Version:   "7.0.2.2",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "rake",
					Version:   "13.0.6",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "strscan",
					Version:   "3.0.1",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "thor",
					Version:   "1.2.1",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "timeout",
					Version:   "0.2.0",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "tzinfo",
					Version:   "2.0.4",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "websocket-driver",
					Version:   "0.7.5",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "websocket-extensions",
					Version:   "0.1.5",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "zeitwerk",
					Version:   "2.5.4",
					Locations: []string{"testdata/rails.lock"},
				},
				{
					Name:      "nokogiri",
					Version:   "1.13.3",
					Locations: []string{"testdata/rails.lock"},
				},
			},
		},
		{
			Name: "rubocop",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/rubocop.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "ast",
					Version:   "2.4.2",
					Locations: []string{"testdata/rubocop.lock"},
				},
				{
					Name:      "parallel",
					Version:   "1.21.0",
					Locations: []string{"testdata/rubocop.lock"},
				},
				{
					Name:      "parser",
					Version:   "3.1.1.0",
					Locations: []string{"testdata/rubocop.lock"},
				},
				{
					Name:      "rainbow",
					Version:   "3.1.1",
					Locations: []string{"testdata/rubocop.lock"},
				},
				{
					Name:      "regexp_parser",
					Version:   "2.2.1",
					Locations: []string{"testdata/rubocop.lock"},
				},
				{
					Name:      "rexml",
					Version:   "3.2.5",
					Locations: []string{"testdata/rubocop.lock"},
				},
				{
					Name:      "rubocop",
					Version:   "1.25.1",
					Locations: []string{"testdata/rubocop.lock"},
				},
				{
					Name:      "rubocop-ast",
					Version:   "1.16.0",
					Locations: []string{"testdata/rubocop.lock"},
				},
				{
					Name:      "ruby-progressbar",
					Version:   "1.11.0",
					Locations: []string{"testdata/rubocop.lock"},
				},
				{
					Name:      "unicode-display_width",
					Version:   "2.1.0",
					Locations: []string{"testdata/rubocop.lock"},
				},
			},
		},
		{
			Name: "has local gem",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/has-local-gem.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "backbone-on-rails",
					Version:   "1.2.0.0",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "actionpack",
					Version:   "7.0.2.2",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "actionview",
					Version:   "7.0.2.2",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "activesupport",
					Version:   "7.0.2.2",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "builder",
					Version:   "3.2.4",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "coffee-script",
					Version:   "2.4.1",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "coffee-script-source",
					Version:   "1.12.2",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "concurrent-ruby",
					Version:   "1.1.9",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "crass",
					Version:   "1.0.6",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "eco",
					Version:   "1.0.0",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "ejs",
					Version:   "1.1.1",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "erubi",
					Version:   "1.10.0",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "execjs",
					Version:   "2.8.1",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "i18n",
					Version:   "1.10.0",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "jquery-rails",
					Version:   "4.4.0",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "loofah",
					Version:   "2.14.0",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "method_source",
					Version:   "1.0.0",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "minitest",
					Version:   "5.15.0",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "racc",
					Version:   "1.6.0",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "rack",
					Version:   "2.2.3",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "rack-test",
					Version:   "1.1.0",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "rails-dom-testing",
					Version:   "2.0.3",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "rails-html-sanitizer",
					Version:   "1.4.2",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "railties",
					Version:   "7.0.2.2",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "rake",
					Version:   "13.0.6",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "thor",
					Version:   "1.2.1",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "tzinfo",
					Version:   "2.0.4",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "zeitwerk",
					Version:   "2.5.4",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "nokogiri",
					Version:   "1.13.3",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
				{
					Name:      "eco-source",
					Version:   "1.1.0.rc.1",
					Locations: []string{"testdata/has-local-gem.lock"},
				},
			},
		},
		{
			Name: "has git gem",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/has-git-gem.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "hanami-controller",
					Version:   "2.0.0.alpha1",
					Locations: []string{"testdata/has-git-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "027dbe2e56397b534e859fc283990cad1b6addd6",
					},
				},
				{
					Name:      "hanami-utils",
					Version:   "2.0.0.alpha1",
					Locations: []string{"testdata/has-git-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "5904fc9a70683b8749aa2861257d0c8c01eae4aa",
					},
				},
				{
					Name:      "concurrent-ruby",
					Version:   "1.1.7",
					Locations: []string{"testdata/has-git-gem.lock"},
				},
				{
					Name:      "rack",
					Version:   "2.2.3",
					Locations: []string{"testdata/has-git-gem.lock"},
				},
				{
					Name:      "transproc",
					Version:   "1.1.1",
					Locations: []string{"testdata/has-git-gem.lock"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := gemfilelock.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

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
