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

package gemfilelock_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
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
			inputPath: "gems.locked",
			want:      true,
		},
		{
			inputPath: "path/to/my/Gemfile.lock",
			want:      true,
		},
		{
			inputPath: "path/to/my/gems.locked",
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
			e, err := gemfilelock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("gemfilelock.New: %v", err)
			}
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
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "no gem section",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-gem-section.lock",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "no gems",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-gems.lock",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "invalid spec",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.lock",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one gem",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-gem.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "ast",
					Version:  "2.4.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/one-gem.lock", 4),
				},
			},
		},
		{
			Name: "trailing source section ",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/source-section-at-end.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "ast",
					Version:  "2.4.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/source-section-at-end.lock", 16),
				},
			},
		},
		{
			Name: "some gems",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/some-gems.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "coderay",
					Version:  "1.1.3",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/some-gems.lock", 4),
				},
				{
					Name:     "method_source",
					Version:  "1.0.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/some-gems.lock", 5),
				},
				{
					Name:     "pry",
					Version:  "0.14.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/some-gems.lock", 6),
				},
			},
		},
		{
			Name: "multiple gems",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple-gems.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "bundler-audit",
					Version:  "0.9.0.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/multiple-gems.lock", 4),
				},
				{
					Name:     "coderay",
					Version:  "1.1.3",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/multiple-gems.lock", 7),
				},
				{
					Name:     "dotenv",
					Version:  "2.7.6",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/multiple-gems.lock", 8),
				},
				{
					Name:     "method_source",
					Version:  "1.0.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/multiple-gems.lock", 9),
				},
				{
					Name:     "pry",
					Version:  "0.14.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/multiple-gems.lock", 10),
				},
				{
					Name:     "thor",
					Version:  "1.2.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/multiple-gems.lock", 13),
				},
			},
		},
		{
			Name: "rails",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/rails.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "actioncable",
					Version:  "7.0.2.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 4),
				},
				{
					Name:     "actionmailbox",
					Version:  "7.0.2.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 9),
				},
				{
					Name:     "actionmailer",
					Version:  "7.0.2.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 19),
				},
				{
					Name:     "actionpack",
					Version:  "7.0.2.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 29),
				},
				{
					Name:     "actiontext",
					Version:  "7.0.2.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 36),
				},
				{
					Name:     "actionview",
					Version:  "7.0.2.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 43),
				},
				{
					Name:     "activejob",
					Version:  "7.0.2.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 49),
				},
				{
					Name:     "activemodel",
					Version:  "7.0.2.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 52),
				},
				{
					Name:     "activerecord",
					Version:  "7.0.2.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 54),
				},
				{
					Name:     "activestorage",
					Version:  "7.0.2.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 57),
				},
				{
					Name:     "activesupport",
					Version:  "7.0.2.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 64),
				},
				{
					Name:     "builder",
					Version:  "3.2.4",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 69),
				},
				{
					Name:     "concurrent-ruby",
					Version:  "1.1.9",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 70),
				},
				{
					Name:     "crass",
					Version:  "1.0.6",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 71),
				},
				{
					Name:     "digest",
					Version:  "3.1.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 72),
				},
				{
					Name:     "erubi",
					Version:  "1.10.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 73),
				},
				{
					Name:     "globalid",
					Version:  "1.0.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 74),
				},
				{
					Name:     "i18n",
					Version:  "1.10.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 76),
				},
				{
					Name:     "io-wait",
					Version:  "0.2.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 78),
				},
				{
					Name:     "loofah",
					Version:  "2.14.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 79),
				},
				{
					Name:     "mail",
					Version:  "2.7.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 82),
				},
				{
					Name:     "marcel",
					Version:  "1.0.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 84),
				},
				{
					Name:     "method_source",
					Version:  "1.0.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 85),
				},
				{
					Name:     "mini_mime",
					Version:  "1.1.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 86),
				},
				{
					Name:     "minitest",
					Version:  "5.15.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 87),
				},
				{
					Name:     "net-imap",
					Version:  "0.2.3",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 88),
				},
				{
					Name:     "net-pop",
					Version:  "0.1.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 92),
				},
				{
					Name:     "net-protocol",
					Version:  "0.1.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 96),
				},
				{
					Name:     "net-smtp",
					Version:  "0.3.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 99),
				},
				{
					Name:     "nio4r",
					Version:  "2.5.8",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 103),
				},
				{
					Name:     "racc",
					Version:  "1.6.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 106),
				},
				{
					Name:     "rack",
					Version:  "2.2.3",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 107),
				},
				{
					Name:     "rack-test",
					Version:  "1.1.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 108),
				},
				{
					Name:     "rails",
					Version:  "7.0.2.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 110),
				},
				{
					Name:     "rails-dom-testing",
					Version:  "2.0.3",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 124),
				},
				{
					Name:     "rails-html-sanitizer",
					Version:  "1.4.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 127),
				},
				{
					Name:     "railties",
					Version:  "7.0.2.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 129),
				},
				{
					Name:     "rake",
					Version:  "13.0.6",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 136),
				},
				{
					Name:     "strscan",
					Version:  "3.0.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 137),
				},
				{
					Name:     "thor",
					Version:  "1.2.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 138),
				},
				{
					Name:     "timeout",
					Version:  "0.2.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 139),
				},
				{
					Name:     "tzinfo",
					Version:  "2.0.4",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 140),
				},
				{
					Name:     "websocket-driver",
					Version:  "0.7.5",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 142),
				},
				{
					Name:     "websocket-extensions",
					Version:  "0.1.5",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 144),
				},
				{
					Name:     "zeitwerk",
					Version:  "2.5.4",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 145),
				},
				{
					Name:     "nokogiri",
					Version:  "1.13.3",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rails.lock", 104),
				},
			},
		},
		{
			Name: "rubocop",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/rubocop.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "ast",
					Version:  "2.4.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rubocop.lock", 4),
				},
				{
					Name:     "parallel",
					Version:  "1.21.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rubocop.lock", 5),
				},
				{
					Name:     "parser",
					Version:  "3.1.1.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rubocop.lock", 6),
				},
				{
					Name:     "rainbow",
					Version:  "3.1.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rubocop.lock", 8),
				},
				{
					Name:     "regexp_parser",
					Version:  "2.2.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rubocop.lock", 9),
				},
				{
					Name:     "rexml",
					Version:  "3.2.5",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rubocop.lock", 10),
				},
				{
					Name:     "rubocop",
					Version:  "1.25.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rubocop.lock", 11),
				},
				{
					Name:     "rubocop-ast",
					Version:  "1.16.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rubocop.lock", 20),
				},
				{
					Name:     "ruby-progressbar",
					Version:  "1.11.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rubocop.lock", 22),
				},
				{
					Name:     "unicode-display_width",
					Version:  "2.1.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/rubocop.lock", 23),
				},
			},
		},
		{
			Name: "has local gem",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/has-local-gem.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "backbone-on-rails",
					Version:  "1.2.0.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 4),
				},
				{
					Name:     "actionpack",
					Version:  "7.0.2.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 14),
				},
				{
					Name:     "actionview",
					Version:  "7.0.2.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 21),
				},
				{
					Name:     "activesupport",
					Version:  "7.0.2.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 27),
				},
				{
					Name:     "builder",
					Version:  "3.2.4",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 32),
				},
				{
					Name:     "coffee-script",
					Version:  "2.4.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 33),
				},
				{
					Name:     "coffee-script-source",
					Version:  "1.12.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 36),
				},
				{
					Name:     "concurrent-ruby",
					Version:  "1.1.9",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 37),
				},
				{
					Name:     "crass",
					Version:  "1.0.6",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 38),
				},
				{
					Name:     "eco",
					Version:  "1.0.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 39),
				},
				{
					Name:     "ejs",
					Version:  "1.1.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 44),
				},
				{
					Name:     "erubi",
					Version:  "1.10.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 45),
				},
				{
					Name:     "execjs",
					Version:  "2.8.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 46),
				},
				{
					Name:     "i18n",
					Version:  "1.10.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 47),
				},
				{
					Name:     "jquery-rails",
					Version:  "4.4.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 49),
				},
				{
					Name:     "loofah",
					Version:  "2.14.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 53),
				},
				{
					Name:     "method_source",
					Version:  "1.0.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 56),
				},
				{
					Name:     "minitest",
					Version:  "5.15.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 57),
				},
				{
					Name:     "racc",
					Version:  "1.6.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 60),
				},
				{
					Name:     "rack",
					Version:  "2.2.3",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 61),
				},
				{
					Name:     "rack-test",
					Version:  "1.1.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 62),
				},
				{
					Name:     "rails-dom-testing",
					Version:  "2.0.3",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 64),
				},
				{
					Name:     "rails-html-sanitizer",
					Version:  "1.4.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 67),
				},
				{
					Name:     "railties",
					Version:  "7.0.2.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 69),
				},
				{
					Name:     "rake",
					Version:  "13.0.6",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 76),
				},
				{
					Name:     "thor",
					Version:  "1.2.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 77),
				},
				{
					Name:     "tzinfo",
					Version:  "2.0.4",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 78),
				},
				{
					Name:     "zeitwerk",
					Version:  "2.5.4",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 80),
				},
				{
					Name:     "nokogiri",
					Version:  "1.13.3",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 58),
				},
				{
					Name:     "eco-source",
					Version:  "1.1.0.rc.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-local-gem.lock", 43),
				},
			},
		},
		{
			Name: "has git gem",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/has-git-gem.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "hanami-controller",
					Version:  "2.0.0.alpha1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-git-gem.lock", 6),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "027dbe2e56397b534e859fc283990cad1b6addd6",
					},
				},
				{
					Name:     "hanami-utils",
					Version:  "2.0.0.alpha1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-git-gem.lock", 15),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "5904fc9a70683b8749aa2861257d0c8c01eae4aa",
					},
				},
				{
					Name:     "concurrent-ruby",
					Version:  "1.1.7",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-git-gem.lock", 22),
				},
				{
					Name:     "rack",
					Version:  "2.2.3",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-git-gem.lock", 23),
				},
				{
					Name:     "transproc",
					Version:  "1.1.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPathAndLine("testdata/has-git-gem.lock", 24),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := gemfilelock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("gemfilelock.New: %v", err)
			}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
