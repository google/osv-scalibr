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

package gem_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
	"gopkg.in/yaml.v3"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name                  string
		path                  string
		isDir                 bool
		fileSizeBytes         int64
		maxFileSizeBytes      int64
		hasPluginSpecific     bool
		pluginSpecificMaxSize int64
		wantRequired          bool
		wantResultMetric      stats.FileRequiredResult
	}{
		{
			name:             ".gem at root",
			path:             "rails.gem",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             ".gem nested path",
			path:             "testdata/aws-sdk-core-3.218.0.gem",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         ".gem directory",
			path:         "testdata/my.gem",
			isDir:        true,
			wantRequired: false,
		},
		{
			name:         "metadata.gz at root",
			path:         "metadata.gz",
			wantRequired: false,
		},
		{
			name:         "metadata.gz nested path",
			path:         "testdata/metadata.gz",
			wantRequired: false,
		},
		{
			name:         "not a gem or metadata file",
			path:         "testdata/test.rb",
			wantRequired: false,
		},
		{
			name:         "data.tar.gz inside gem archive",
			path:         "data.tar.gz",
			wantRequired: false,
		},
		{
			name:             ".gem required if size less than maxFileSizeBytes",
			path:             "test.gem",
			fileSizeBytes:    10 * units.MiB,
			maxFileSizeBytes: 20 * units.MiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             ".gem required if size equal to maxFileSizeBytes",
			path:             "test.gem",
			fileSizeBytes:    10 * units.MiB,
			maxFileSizeBytes: 10 * units.MiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             ".gem not required if size greater than maxFileSizeBytes",
			path:             "test.gem",
			fileSizeBytes:    50 * units.MiB,
			maxFileSizeBytes: 10 * units.MiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:                  ".gem size exceeds plugin-specific maxFileSizeBytes override",
			path:                  "test.gem",
			fileSizeBytes:         15 * units.MiB,
			maxFileSizeBytes:      20 * units.MiB,
			hasPluginSpecific:     true,
			pluginSpecificMaxSize: 10 * units.MiB,
			wantRequired:          false,
			wantResultMetric:      stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:                  ".gem size allowed by plugin-specific maxFileSizeBytes override",
			path:                  "test.gem",
			fileSizeBytes:         15 * units.MiB,
			maxFileSizeBytes:      10 * units.MiB,
			hasPluginSpecific:     true,
			pluginSpecificMaxSize: 20 * units.MiB,
			wantRequired:          true,
			wantResultMetric:      stats.FileRequiredResultOK,
		},
		{
			name:                  "plugin-specific maxFileSizeBytes of 0 retains global limit",
			path:                  "test.gem",
			fileSizeBytes:         15 * units.MiB,
			maxFileSizeBytes:      20 * units.MiB,
			hasPluginSpecific:     true,
			pluginSpecificMaxSize: 0,
			wantRequired:          true,
			wantResultMetric:      stats.FileRequiredResultOK,
		},
		{
			name:             ".gem required if size within default maxFileSizeBytes",
			path:             "test.gem",
			fileSizeBytes:    20 * units.MiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             ".gem not required if size exceeds default maxFileSizeBytes",
			path:             "test.gem",
			fileSizeBytes:    20*units.MiB + 1,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			cfg := &cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes}
			if tt.hasPluginSpecific {
				cfg.PluginSpecific = []*cpb.PluginSpecificConfig{
					{Config: &cpb.PluginSpecificConfig_RubyGem{
						RubyGem: &cpb.RubyGemConfig{
							MaxFileSizeBytes: tt.pluginSpecificMaxSize,
						},
					}},
				}
			}
			e, err := gem.New(cfg)
			if err != nil {
				t.Fatalf("gem.New: %v", err)
			}
			e.(*gem.Extractor).Stats = collector

			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1 * units.KiB
			}

			mode := fs.ModePerm
			if tt.isDir {
				mode |= fs.ModeDir
			}

			isRequired := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: path.Base(tt.path),
				FileMode: mode,
				FileSize: fileSizeBytes,
			}))
			if isRequired != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantRequired)
			}

			gotResultMetric := collector.FileRequiredResult(tt.path)
			if gotResultMetric != tt.wantResultMetric {
				t.Errorf("FileRequired(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}
		})
	}
}

func TestFileRequiredNoLimitAndNilStats(t *testing.T) {
	// Zero-value extractor has maxFileSizeBytes = 0 and Stats = nil.
	var e gem.Extractor
	isRequired := e.FileRequired(simplefileapi.New("test.gem", fakefs.FakeFileInfo{
		FileName: "test.gem",
		FileMode: fs.ModePerm,
		FileSize: 100,
	}))
	if !isRequired {
		t.Errorf("FileRequired with maxFileSizeBytes=0 got %v, want true", isRequired)
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		includeDeps      bool
		wantPackages     []*extractor.Package
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name:        "aws-sdk-core without dependencies",
			path:        "testdata/aws-sdk-core-3.218.0.gem",
			includeDeps: false,
			wantPackages: []*extractor.Package{
				{
					Name:     "aws-sdk-core",
					Version:  "3.218.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/aws-sdk-core-3.218.0.gem"),
					Metadata: &gem.RubyGemMetadata{
						Authors:     []string{"Amazon Web Services"},
						Description: "Provides API clients for AWS. This gem is part of the official AWS SDK for Ruby.",
						Homepage:    "https://github.com/aws/aws-sdk-ruby",
						Licenses:    []string{"Apache-2.0"},
						Platform:    "ruby",
						Summary:     "AWS SDK for Ruby - Core",
					},
				},
			},
		},
		{
			name:        "aws-sdk-core with dependencies",
			path:        "testdata/aws-sdk-core-3.218.0.gem",
			includeDeps: true,
			wantPackages: []*extractor.Package{
				{
					Name:     "aws-sdk-core",
					Version:  "3.218.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/aws-sdk-core-3.218.0.gem"),
					Metadata: &gem.RubyGemMetadata{
						Authors:     []string{"Amazon Web Services"},
						Description: "Provides API clients for AWS. This gem is part of the official AWS SDK for Ruby.",
						Homepage:    "https://github.com/aws/aws-sdk-ruby",
						Licenses:    []string{"Apache-2.0"},
						Platform:    "ruby",
						Summary:     "AWS SDK for Ruby - Core",
					},
				},
				{
					Name:     "jmespath",
					Version:  "1.6.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/aws-sdk-core-3.218.0.gem"),
				},
				{
					Name:     "aws-partitions",
					Version:  "1.992.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/aws-sdk-core-3.218.0.gem"),
				},
				{
					Name:     "aws-sigv4",
					Version:  "1.9.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/aws-sdk-core-3.218.0.gem"),
				},
				{
					Name:     "aws-eventstream",
					Version:  "1.3.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/aws-sdk-core-3.218.0.gem"),
				},
			},
		},
		{
			name:        "faraday without dependencies",
			path:        "testdata/faraday-2.12.2.gem",
			includeDeps: false,
			wantPackages: []*extractor.Package{
				{
					Name:     "faraday",
					Version:  "2.12.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/faraday-2.12.2.gem"),
					Metadata: &gem.RubyGemMetadata{
						Authors:     []string{"@technoweenie", "@iMacTia", "@olleolleolle"},
						Description: "",
						Homepage:    "https://lostisland.github.io/faraday",
						Licenses:    []string{"MIT"},
						Platform:    "ruby",
						Summary:     "HTTP/REST API client library.",
					},
				},
			},
		},
		{
			name:        "faraday with dependencies",
			path:        "testdata/faraday-2.12.2.gem",
			includeDeps: true,
			wantPackages: []*extractor.Package{
				{
					Name:     "faraday",
					Version:  "2.12.2",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/faraday-2.12.2.gem"),
					Metadata: &gem.RubyGemMetadata{
						Authors:     []string{"@technoweenie", "@iMacTia", "@olleolleolle"},
						Description: "",
						Homepage:    "https://lostisland.github.io/faraday",
						Licenses:    []string{"MIT"},
						Platform:    "ruby",
						Summary:     "HTTP/REST API client library.",
					},
				},
				{
					Name:     "faraday-net_http",
					Version:  "2.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/faraday-2.12.2.gem"),
				},
				{
					Name:     "json",
					Version:  "0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/faraday-2.12.2.gem"),
				},
				{
					Name:     "logger",
					Version:  "0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/faraday-2.12.2.gem"),
				},
			},
		},
		{
			name:        "rack with only dev dependencies returns no runtime dependencies",
			path:        "testdata/rack-3.1.8.gem",
			includeDeps: true,
			wantPackages: []*extractor.Package{
				{
					Name:     "rack",
					Version:  "3.1.8",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/rack-3.1.8.gem"),
					Metadata: &gem.RubyGemMetadata{
						Authors: []string{"Leah Neukirchen"},
						Description: "Rack provides a minimal, modular and adaptable interface for developing\n" +
							"web applications in Ruby. By wrapping HTTP requests and responses in\n" +
							"the simplest way possible, it unifies and distills the API for web\n" +
							"servers, web frameworks, and software in between (the so-called\n" +
							"middleware) into a single method call.\n",
						Homepage: "https://github.com/rack/rack",
						Licenses: []string{"MIT"},
						Platform: "ruby",
						Summary:  "A modular Ruby webserver interface.",
					},
				},
			},
		},
		{
			name:        "synthetic gem with exact versions, twiddle-wakka normalization, and skips",
			path:        "testdata/synthetic_exact-1.0.0.gem",
			includeDeps: true,
			wantPackages: []*extractor.Package{
				{
					Name:     "synthetic-gem",
					Version:  "1.0.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/synthetic_exact-1.0.0.gem"),
					Metadata: &gem.RubyGemMetadata{
						Authors:     []string{"Test Author"},
						Description: "Synthetic test gem.",
						Homepage:    "https://example.com/synthetic",
						Licenses:    []string{"MIT"},
						Platform:    "ruby",
						Summary:     "Synthetic test gem.",
					},
				},
				{
					Name:     "exact-dep",
					Version:  "2.0.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/synthetic_exact-1.0.0.gem"),
				},
				{
					Name:     "twiddle-single",
					Version:  "1.0.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/synthetic_exact-1.0.0.gem"),
				},
				{
					Name:     "twiddle-double",
					Version:  "2.3.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/synthetic_exact-1.0.0.gem"),
				},
				{
					Name:     "twiddle-triple",
					Version:  "4.5.6",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/synthetic_exact-1.0.0.gem"),
				},
			},
		},
		{
			name:             "corrupt gem archive",
			path:             "testdata/corrupt.gem",
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "corrupt metadata inside gem",
			path:             "testdata/corrupt_metadata.gem",
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := os.Open(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := r.Close(); err != nil {
					t.Errorf("Close(): %v", err)
				}
			}()

			info, err := os.Stat(tt.path)
			if err != nil {
				t.Fatal(err)
			}

			collector := testcollector.New()
			input := &filesystem.ScanInput{
				FS:     scalibrfs.DirFS("."),
				Path:   tt.path,
				Reader: r,
				Info:   info,
			}
			cfg := &cpb.PluginConfig{
				PluginSpecific: []*cpb.PluginSpecificConfig{
					{Config: &cpb.PluginSpecificConfig_RubyGem{
						RubyGem: &cpb.RubyGemConfig{
							IncludeDependencies: tt.includeDeps,
						},
					}},
				},
			}
			e, err := gem.New(cfg)
			if err != nil {
				t.Fatalf("gem.New: %v", err)
			}
			e.(*gem.Extractor).Stats = collector
			got, err := e.Extract(t.Context(), input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.name, err, tt.wantErr)
			}

			var want inventory.Inventory
			if tt.wantPackages != nil {
				want = inventory.Inventory{Packages: tt.wantPackages}
			}

			if diff := cmp.Diff(
				want,
				got,
				cmpopts.SortSlices(extracttest.PackageCmpLess),
				cmpopts.EquateEmpty(),
				cmpopts.IgnoreFields(gem.RubyGemMetadata{}, "Dependencies"),
			); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}

			wantResultMetric := tt.wantResultMetric
			if wantResultMetric == "" && tt.wantErr == nil {
				wantResultMetric = stats.FileExtractedResultSuccess
			}
			gotResultMetric := collector.FileExtractedResult(tt.path)
			if gotResultMetric != wantResultMetric {
				t.Errorf("Extract(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, wantResultMetric)
			}

			gotFileSizeMetric := collector.FileExtractedFileSize(tt.path)
			if gotFileSizeMetric != info.Size() {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", tt.path, gotFileSizeMetric, info.Size())
			}
		})
	}
}

func TestNormalizeTwiddleWakka(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1", "1.0.0"},
		{"2.3", "2.3.0"},
		{"4.5.6", "4.5.6"},
		{"1.2.3.4", "1.2.3.4"},
		{"0", "0.0.0"},
		{"0.1", "0.1.0"},
	}

	for _, tt := range tests {
		got := gem.NormalizeTwiddleWakka(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeTwiddleWakka(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestResolveDependencyVersion(t *testing.T) {
	tests := []struct {
		name    string
		reqs    []gem.RequirementConstraint
		wantVer string
		wantOK  bool
	}{
		{
			name: "exact version",
			reqs: []gem.RequirementConstraint{
				{Operator: "=", Version: "2.1.0"},
			},
			wantVer: "2.1.0",
			wantOK:  true,
		},
		{
			name: "greater than or equal",
			reqs: []gem.RequirementConstraint{
				{Operator: ">=", Version: "1.5"},
			},
			wantVer: "1.5",
			wantOK:  true,
		},
		{
			name: "twiddle single segment",
			reqs: []gem.RequirementConstraint{
				{Operator: "~>", Version: "1"},
			},
			wantVer: "1.0.0",
			wantOK:  true,
		},
		{
			name: "twiddle two segments",
			reqs: []gem.RequirementConstraint{
				{Operator: "~>", Version: "1.9"},
			},
			wantVer: "1.9.0",
			wantOK:  true,
		},
		{
			name: "twiddle three segments",
			reqs: []gem.RequirementConstraint{
				{Operator: "~>", Version: "2.3.4"},
			},
			wantVer: "2.3.4",
			wantOK:  true,
		},
		{
			name: "multiple lower bounds picks highest",
			reqs: []gem.RequirementConstraint{
				{Operator: "~>", Version: "1"},
				{Operator: ">=", Version: "1.6.1"},
			},
			wantVer: "1.6.1",
			wantOK:  true,
		},
		{
			name: "lower and upper bound picks lower bound",
			reqs: []gem.RequirementConstraint{
				{Operator: ">=", Version: "2.0"},
				{Operator: "<", Version: "3.5"},
			},
			wantVer: "2.0",
			wantOK:  true,
		},
		{
			name: "only upper bounds returns false",
			reqs: []gem.RequirementConstraint{
				{Operator: "<", Version: "3.0.0"},
				{Operator: "<=", Version: "2.5.0"},
				{Operator: "!=", Version: "1.0.0"},
			},
			wantVer: "",
			wantOK:  false,
		},
		{
			name:    "empty requirements returns false",
			reqs:    []gem.RequirementConstraint{},
			wantVer: "",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVer, gotOK := gem.ResolveDependencyVersion(tt.reqs)
			if gotOK != tt.wantOK || gotVer != tt.wantVer {
				t.Errorf("ResolveDependencyVersion(%+v) = (%q, %v), want (%q, %v)", tt.reqs, gotVer, gotOK, tt.wantVer, tt.wantOK)
			}
		})
	}
}

func TestRubyGemMetadataDependencies(t *testing.T) {
	r, err := os.Open("testdata/synthetic_exact-1.0.0.gem")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	info, err := os.Stat("testdata/synthetic_exact-1.0.0.gem")
	if err != nil {
		t.Fatal(err)
	}

	e, err := gem.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("gem.New: %v", err)
	}

	res, err := e.Extract(t.Context(), &filesystem.ScanInput{
		FS:     scalibrfs.DirFS("."),
		Path:   "testdata/synthetic_exact-1.0.0.gem",
		Reader: r,
		Info:   info,
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if len(res.Packages) != 1 {
		t.Fatalf("expected 1 root package, got %d", len(res.Packages))
	}

	meta, ok := res.Packages[0].Metadata.(*gem.RubyGemMetadata)
	if !ok || meta == nil {
		t.Fatalf("expected *gem.RubyGemMetadata, got %T", res.Packages[0].Metadata)
	}

	// Verify raw dependencies list in metadata
	if len(meta.Dependencies) != 6 {
		t.Fatalf("expected 6 dependencies in metadata, got %d", len(meta.Dependencies))
	}

	// Verify IsRuntime() on runtime and development dependencies
	for _, dep := range meta.Dependencies {
		if dep.Name == "dev-dep" {
			if dep.IsRuntime() {
				t.Errorf("expected dev-dep to not be runtime")
			}
		} else {
			if !dep.IsRuntime() {
				t.Errorf("expected %s to be runtime", dep.Name)
			}
		}
	}
}

func TestNewConfig(t *testing.T) {
	tests := []struct {
		name                 string
		cfg                  *cpb.PluginConfig
		wantName             string
		wantVersion          int
		wantMaxFileSizeBytes int64
	}{
		{
			name:                 "default config",
			cfg:                  &cpb.PluginConfig{},
			wantName:             "ruby/gem",
			wantVersion:          0,
			wantMaxFileSizeBytes: 20 * units.MiB,
		},
		{
			name:                 "generic max file size",
			cfg:                  &cpb.PluginConfig{MaxFileSizeBytes: 20 * units.MiB},
			wantName:             "ruby/gem",
			wantVersion:          0,
			wantMaxFileSizeBytes: 20 * units.MiB,
		},
		{
			name: "plugin specific max file size overrides generic",
			cfg: &cpb.PluginConfig{
				MaxFileSizeBytes: 20 * units.MiB,
				PluginSpecific: []*cpb.PluginSpecificConfig{
					{Config: &cpb.PluginSpecificConfig_RubyGem{
						RubyGem: &cpb.RubyGemConfig{
							MaxFileSizeBytes: 50 * units.MiB,
						},
					}},
				},
			},
			wantName:             "ruby/gem",
			wantVersion:          0,
			wantMaxFileSizeBytes: 50 * units.MiB,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := gem.New(tt.cfg)
			if err != nil {
				t.Fatalf("gem.New(%v): %v", tt.cfg, err)
			}
			if e.Name() != tt.wantName {
				t.Errorf("e.Name() = %q, want %q", e.Name(), tt.wantName)
			}
			if e.Version() != tt.wantVersion {
				t.Errorf("e.Version() = %d, want %d", e.Version(), tt.wantVersion)
			}
			if reqs := e.Requirements(); reqs == nil {
				t.Errorf("e.Requirements() is nil")
			}
			if tt.wantMaxFileSizeBytes > 0 {
				if !e.FileRequired(simplefileapi.New("test.gem", fakefs.FakeFileInfo{
					FileName: "test.gem",
					FileMode: fs.ModePerm,
					FileSize: tt.wantMaxFileSizeBytes,
				})) {
					t.Errorf("FileRequired(%d bytes) = false, want true", tt.wantMaxFileSizeBytes)
				}
				if e.FileRequired(simplefileapi.New("test.gem", fakefs.FakeFileInfo{
					FileName: "test.gem",
					FileMode: fs.ModePerm,
					FileSize: tt.wantMaxFileSizeBytes + 1,
				})) {
					t.Errorf("FileRequired(%d bytes) = true, want false", tt.wantMaxFileSizeBytes+1)
				}
			}
		})
	}
}

func TestYAMLVersionShapes(t *testing.T) {
	// Tests unmarshaling both YAML version shapes:
	// 1. Ruby Object Mapping (!ruby/object:Gem::Version) produced by Psych
	// 2. Plain Scalar String produced by custom tools or simplified specs
	// 3. Mixed shapes within the same dependency requirement list
	tests := []struct {
		name        string
		yamlData    string
		wantDepName string
		wantReqs    []gem.RequirementConstraint
		wantVersion string
		wantOK      bool
	}{
		{
			name: "ruby object mapping version (!ruby/object:Gem::Version)",
			yamlData: `
name: rack
type: :runtime
requirement:
  requirements:
  - - "~>"
    - !ruby/object:Gem::Version
      version: '2.1.0'
  - - ">="
    - !ruby/object:Gem::Version
      version: '2.0'
`,
			wantDepName: "rack",
			wantReqs: []gem.RequirementConstraint{
				{Operator: "~>", Version: "2.1.0"},
				{Operator: ">=", Version: "2.0"},
			},
			wantVersion: "2.1.0",
			wantOK:      true,
		},
		{
			name: "plain scalar string version",
			yamlData: `
name: sinatra
type: :runtime
requirement:
  requirements:
  - - ">="
    - '1.4.0'
  - - "<"
    - '3.0.0'
`,
			wantDepName: "sinatra",
			wantReqs: []gem.RequirementConstraint{
				{Operator: ">=", Version: "1.4.0"},
				{Operator: "<", Version: "3.0.0"},
			},
			wantVersion: "1.4.0",
			wantOK:      true,
		},
		{
			name: "mixed mapping and scalar version shapes",
			yamlData: `
name: faraday
type: :runtime
requirement:
  requirements:
  - - "~>"
    - !ruby/object:Gem::Version
      version: '1.8'
  - - ">="
    - '1.8.2'
`,
			wantDepName: "faraday",
			wantReqs: []gem.RequirementConstraint{
				{Operator: "~>", Version: "1.8"},
				{Operator: ">=", Version: "1.8.2"},
			},
			wantVersion: "1.8.2",
			wantOK:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dep gem.Dependency
			if err := yaml.Unmarshal([]byte(tt.yamlData), &dep); err != nil {
				t.Fatalf("yaml.Unmarshal: %v", err)
			}
			if dep.Name != tt.wantDepName {
				t.Errorf("dep.Name = %q, want %q", dep.Name, tt.wantDepName)
			}
			if !dep.IsRuntime() {
				t.Errorf("dep.IsRuntime() = false, want true")
			}
			gotReqs := dep.Requirements()
			if diff := cmp.Diff(tt.wantReqs, gotReqs); diff != "" {
				t.Errorf("dep.Requirements() mismatch (-want +got):\n%s", diff)
			}
			gotVer, gotOK := gem.ResolveDependencyVersion(gotReqs)
			if gotOK != tt.wantOK || gotVer != tt.wantVersion {
				t.Errorf("ResolveDependencyVersion() = (%q, %v), want (%q, %v)", gotVer, gotOK, tt.wantVersion, tt.wantOK)
			}
		})
	}
}

func TestExtractMissingMetadata(t *testing.T) {
	tarPath := filepath.Join(t.TempDir(), "no_metadata.gem")
	f, err := os.Create(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	if err := tw.WriteHeader(&tar.Header{
		Name: "data.tar.gz",
		Size: 0,
		Mode: 0644,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := os.Open(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	info, err := os.Stat(tarPath)
	if err != nil {
		t.Fatal(err)
	}

	e, err := gem.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatal(err)
	}
	input := &filesystem.ScanInput{
		FS:     scalibrfs.DirFS("."),
		Path:   tarPath,
		Reader: r,
		Info:   info,
	}
	_, err = e.Extract(t.Context(), input)
	if err == nil {
		t.Fatalf("Extract expected error for missing metadata.gz, got nil")
	}
}

func TestExtractNoLimit(t *testing.T) {
	path := "testdata/synthetic_exact-1.0.0.gem"
	r, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// Zero-value extractor has maxFileSizeBytes = 0.
	var e gem.Extractor
	input := &filesystem.ScanInput{
		FS:     scalibrfs.DirFS("."),
		Path:   path,
		Reader: r,
		Info:   info,
	}
	got, err := e.Extract(t.Context(), input)
	if err != nil {
		t.Fatalf("Extract with maxFileSizeBytes=0 failed: %v", err)
	}
	if len(got.Packages) == 0 {
		t.Errorf("expected extracted packages, got none")
	}
}

func TestDependencyRequirementsFallback(t *testing.T) {
	d := &gem.Dependency{
		Name:        "example",
		Requirement: nil,
		VersionRequirements: &gem.Requirement{
			Requirements: []gem.RequirementConstraint{
				{Operator: ">=", Version: "1.2.3"},
			},
		},
	}
	reqs := d.Requirements()
	if len(reqs) != 1 || reqs[0].Version != "1.2.3" || reqs[0].Operator != ">=" {
		t.Fatalf("Requirements() = %+v, want [{>= 1.2.3}]", reqs)
	}
}

func TestRequirementConstraintUnmarshalYAMLInvalid(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{name: "scalar node", yaml: `"not-a-sequence"`},
		{name: "empty sequence", yaml: `[]`},
		{name: "single element sequence", yaml: `[">="]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c gem.RequirementConstraint
			if err := yaml.Unmarshal([]byte(tt.yaml), &c); err != nil {
				t.Fatalf("Unmarshal(%q) unexpected error: %v", tt.yaml, err)
			}
			if c.Operator != "" || c.Version != "" {
				t.Errorf("expected empty constraint for %q, got %+v", tt.yaml, c)
			}
		})
	}
}

func TestResolveDependencyVersionOrdering(t *testing.T) {
	reqs := []gem.RequirementConstraint{
		{Operator: "=", Version: "1.0.0"},
		{Operator: "=", Version: "3.0.0"},
		{Operator: "=", Version: "2.0.0"},
	}
	best, ok := gem.ResolveDependencyVersion(reqs)
	if !ok || best != "3.0.0" {
		t.Fatalf("ResolveDependencyVersion(%v) = (%q, %v), want (3.0.0, true)", reqs, best, ok)
	}
}

func TestExtractMetadataGzDirectory(t *testing.T) {
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "metadata.gz",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tw.Close: %v", err)
	}

	e := gem.Extractor{}
	_, err := e.Extract(context.Background(), &filesystem.ScanInput{
		Path:   "test.gem",
		Reader: buf,
	})
	if err == nil {
		t.Fatalf("Extract() on gem with metadata.gz directory expected error, got nil")
	}
}

func createTestGemWithMetadata(t *testing.T, metadataYAML string) io.Reader {
	t.Helper()
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	if _, err := gw.Write([]byte(metadataYAML)); err != nil {
		t.Fatalf("gzip.Write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip.Close: %v", err)
	}

	var gemBuf bytes.Buffer
	tw := tar.NewWriter(&gemBuf)
	header := &tar.Header{
		Name: "metadata.gz",
		Size: int64(gzBuf.Len()),
		Mode: 0644,
	}
	if err := tw.WriteHeader(header); err != nil {
		t.Fatalf("tar.WriteHeader: %v", err)
	}
	if _, err := tw.Write(gzBuf.Bytes()); err != nil {
		t.Fatalf("tar.Write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar.Close: %v", err)
	}

	return bytes.NewReader(gemBuf.Bytes())
}

func TestDependencyNilSafety(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var d *gem.Dependency
		if d.IsRuntime() {
			t.Errorf("(*Dependency)(nil).IsRuntime() = true, want false")
		}
		if reqs := d.Requirements(); reqs != nil {
			t.Errorf("(*Dependency)(nil).Requirements() = %v, want nil", reqs)
		}
	})

	t.Run("empty Dependency", func(t *testing.T) {
		d := &gem.Dependency{}
		if !d.IsRuntime() {
			t.Errorf("(&Dependency{}).IsRuntime() = false, want true (default runtime)")
		}
		if reqs := d.Requirements(); reqs != nil {
			t.Errorf("(&Dependency{}).Requirements() = %v, want nil", reqs)
		}
	})

	t.Run("dependency types", func(t *testing.T) {
		tests := []struct {
			depType     string
			wantRuntime bool
		}{
			{depType: "", wantRuntime: true},
			{depType: "runtime", wantRuntime: true},
			{depType: ":runtime", wantRuntime: true},
			{depType: "  :runtime  ", wantRuntime: true},
			{depType: "  runtime  ", wantRuntime: true},
			{depType: ":development", wantRuntime: false},
			{depType: "development", wantRuntime: false},
			{depType: ":other", wantRuntime: false},
			{depType: "test", wantRuntime: false},
		}
		for _, tt := range tests {
			d := &gem.Dependency{Type: tt.depType}
			if got := d.IsRuntime(); got != tt.wantRuntime {
				t.Errorf("(&Dependency{Type: %q}).IsRuntime() = %v, want %v", tt.depType, got, tt.wantRuntime)
			}
		}
	})

	t.Run("requirements fallback and nil handling", func(t *testing.T) {
		// Both nil
		d := &gem.Dependency{Requirement: nil, VersionRequirements: nil}
		if reqs := d.Requirements(); reqs != nil {
			t.Errorf("Requirements() with both nil = %v, want nil", reqs)
		}

		// Requirement non-nil but empty slice, VersionRequirements nil
		d = &gem.Dependency{
			Requirement:         &gem.Requirement{Requirements: []gem.RequirementConstraint{}},
			VersionRequirements: nil,
		}
		if reqs := d.Requirements(); reqs != nil {
			t.Errorf("Requirements() with empty slice = %v, want nil", reqs)
		}

		// Requirement empty slice, VersionRequirements has entries
		d = &gem.Dependency{
			Requirement: &gem.Requirement{Requirements: []gem.RequirementConstraint{}},
			VersionRequirements: &gem.Requirement{
				Requirements: []gem.RequirementConstraint{
					{Operator: ">=", Version: "2.0.0"},
				},
			},
		}
		if reqs := d.Requirements(); len(reqs) != 1 || reqs[0].Version != "2.0.0" {
			t.Errorf("Requirements() fallback = %v, want [{>= 2.0.0}]", reqs)
		}

		// Requirement has entries, VersionRequirements also has entries (Requirement takes precedence)
		d = &gem.Dependency{
			Requirement: &gem.Requirement{
				Requirements: []gem.RequirementConstraint{
					{Operator: "=", Version: "1.0.0"},
				},
			},
			VersionRequirements: &gem.Requirement{
				Requirements: []gem.RequirementConstraint{
					{Operator: ">=", Version: "2.0.0"},
				},
			},
		}
		if reqs := d.Requirements(); len(reqs) != 1 || reqs[0].Version != "1.0.0" {
			t.Errorf("Requirements() primary = %v, want [{= 1.0.0}]", reqs)
		}
	})
}

func TestYAMLUnmarshalNilAndMissingFields(t *testing.T) {
	t.Run("Dependency with null requirements", func(t *testing.T) {
		yamlData := `
name: foo
type: :runtime
requirement: null
version_requirements: null
`
		var d gem.Dependency
		if err := yaml.Unmarshal([]byte(yamlData), &d); err != nil {
			t.Fatalf("Unmarshal Dependency unexpected error: %v", err)
		}
		if d.Name != "foo" {
			t.Errorf("d.Name = %q, want foo", d.Name)
		}
		if !d.IsRuntime() {
			t.Errorf("d.IsRuntime() = false, want true")
		}
		if reqs := d.Requirements(); reqs != nil {
			t.Errorf("d.Requirements() = %v, want nil", reqs)
		}
	})

	t.Run("Dependency with null requirements inside requirement struct", func(t *testing.T) {
		yamlData := `
name: bar
requirement:
  requirements: null
`
		var d gem.Dependency
		if err := yaml.Unmarshal([]byte(yamlData), &d); err != nil {
			t.Fatalf("Unmarshal Dependency unexpected error: %v", err)
		}
		if reqs := d.Requirements(); reqs != nil {
			t.Errorf("d.Requirements() = %v, want nil", reqs)
		}
	})

	t.Run("RequirementConstraint defensive decoding", func(t *testing.T) {
		tests := []struct {
			name    string
			yaml    string
			wantOp  string
			wantVer string
		}{
			{
				name:    "plain scalar version",
				yaml:    `[">=", "1.2.3"]`,
				wantOp:  ">=",
				wantVer: "1.2.3",
			},
			{
				name:    "plain scalar with whitespace",
				yaml:    `["  >=  ", "  1.2.3  "]`,
				wantOp:  ">=",
				wantVer: "1.2.3",
			},
			{
				name:    "ruby object mapping version",
				yaml:    `[">=", !ruby/object:Gem::Version {version: "2.3.4"}]`,
				wantOp:  ">=",
				wantVer: "2.3.4",
			},
			{
				name:    "ruby object mapping missing version key",
				yaml:    `[">=", !ruby/object:Gem::Version {other_key: "2.3.4"}]`,
				wantOp:  ">=",
				wantVer: "",
			},
			{
				name:    "ruby object mapping empty",
				yaml:    `[">=", !ruby/object:Gem::Version {}]`,
				wantOp:  ">=",
				wantVer: "",
			},
			{
				name:    "null version element",
				yaml:    `[">=", null]`,
				wantOp:  ">=",
				wantVer: "",
			},
			{
				name:    "nested sequence version element",
				yaml:    `[">=", [1, 2, 3]]`,
				wantOp:  ">=",
				wantVer: "",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var c gem.RequirementConstraint
				if err := yaml.Unmarshal([]byte(tt.yaml), &c); err != nil {
					t.Fatalf("Unmarshal(%s) unexpected error: %v", tt.yaml, err)
				}
				if c.Operator != tt.wantOp || c.Version != tt.wantVer {
					t.Errorf("Unmarshal(%s) = {Operator: %q, Version: %q}, want {Operator: %q, Version: %q}",
						tt.yaml, c.Operator, c.Version, tt.wantOp, tt.wantVer)
				}
			})
		}
	})
}

func TestResolveDependencyVersionDefensive(t *testing.T) {
	tests := []struct {
		name      string
		reqs      []gem.RequirementConstraint
		wantVer   string
		wantFound bool
	}{
		{
			name:      "nil slice",
			reqs:      nil,
			wantVer:   "",
			wantFound: false,
		},
		{
			name:      "empty slice",
			reqs:      []gem.RequirementConstraint{},
			wantVer:   "",
			wantFound: false,
		},
		{
			name: "empty or whitespace version",
			reqs: []gem.RequirementConstraint{
				{Operator: "=", Version: ""},
				{Operator: ">=", Version: "   "},
			},
			wantVer:   "",
			wantFound: false,
		},
		{
			name: "non-qualifying operators only",
			reqs: []gem.RequirementConstraint{
				{Operator: "<", Version: "2.0.0"},
				{Operator: "<=", Version: "1.5.0"},
				{Operator: "!=", Version: "1.0.0"},
			},
			wantVer:   "",
			wantFound: false,
		},
		{
			name: "twiddle-wakka normalization variations",
			reqs: []gem.RequirementConstraint{
				{Operator: "~>", Version: "2"},
				{Operator: "~>", Version: "1.5"},
				{Operator: "~>", Version: "1.2.3"},
			},
			wantVer:   "2.0.0",
			wantFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVer, gotFound := gem.ResolveDependencyVersion(tt.reqs)
			if gotVer != tt.wantVer || gotFound != tt.wantFound {
				t.Errorf("ResolveDependencyVersion(%v) = (%q, %v), want (%q, %v)",
					tt.reqs, gotVer, gotFound, tt.wantVer, tt.wantFound)
			}
		})
	}
}

func TestExtractDefensiveNilYAML(t *testing.T) {
	tests := []struct {
		name         string
		yaml         string
		includeDeps  bool
		wantPkgs     int
		wantRootName string
		wantErr      bool
	}{
		{
			name: "missing name",
			yaml: `
version: "1.0.0"
summary: "missing name"
`,
			wantPkgs: 0,
		},
		{
			name: "empty name",
			yaml: `
name: ""
version: "1.0.0"
`,
			wantPkgs: 0,
		},
		{
			name: "missing version",
			yaml: `
name: "mypkg"
summary: "missing version"
`,
			wantPkgs: 0,
		},
		{
			name: "null version scalar",
			yaml: `
name: "mypkg"
version: null
`,
			wantPkgs: 0,
		},
		{
			name: "version mapping missing version key",
			yaml: `
name: "mypkg"
version: !ruby/object:Gem::Version
  attributes: {}
`,
			wantPkgs: 0,
		},
		{
			name: "valid root with null dependencies field",
			yaml: `
name: "valid-pkg"
version: "1.2.3"
dependencies: null
`,
			wantPkgs:     1,
			wantRootName: "valid-pkg",
		},
		{
			name: "valid root with dependencies: [null] and includeDeps=true",
			yaml: `
name: "valid-pkg"
version: "1.2.3"
dependencies:
  - null
`,
			includeDeps:  true,
			wantPkgs:     1,
			wantRootName: "valid-pkg",
		},
		{
			name: "dependency with null requirement and includeDeps=true",
			yaml: `
name: "valid-pkg"
version: "1.2.3"
dependencies:
  - name: "dep1"
    type: :runtime
    requirement: null
    version_requirements: null
`,
			includeDeps:  true,
			wantPkgs:     1,
			wantRootName: "valid-pkg",
		},
		{
			name: "dependency with null requirements slice and includeDeps=true",
			yaml: `
name: "valid-pkg"
version: "1.2.3"
dependencies:
  - name: "dep1"
    type: :runtime
    requirement:
      requirements: null
`,
			includeDeps:  true,
			wantPkgs:     1,
			wantRootName: "valid-pkg",
		},
		{
			name: "development dependency excluded when includeDeps=true",
			yaml: `
name: "valid-pkg"
version: "1.2.3"
dependencies:
  - name: "dev-dep"
    type: :development
    requirement:
      requirements:
        - [">=", "1.0.0"]
`,
			includeDeps:  true,
			wantPkgs:     1,
			wantRootName: "valid-pkg",
		},
		{
			name: "runtime dependency with unresolvable constraint (< only)",
			yaml: `
name: "valid-pkg"
version: "1.2.3"
dependencies:
  - name: "dep-unresolvable"
    type: :runtime
    requirement:
      requirements:
        - ["<", "2.0.0"]
`,
			includeDeps:  true,
			wantPkgs:     1,
			wantRootName: "valid-pkg",
		},
		{
			name: "valid runtime dependency with ruby object version mapping",
			yaml: `
name: "valid-pkg"
version: !ruby/object:Gem::Version
  version: "1.2.3"
dependencies:
  - name: "dep-runtime"
    type: :runtime
    requirement:
      requirements:
        - [">=", !ruby/object:Gem::Version {version: "3.0.0"}]
`,
			includeDeps:  true,
			wantPkgs:     2,
			wantRootName: "valid-pkg",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &cpb.PluginConfig{}
			if tt.includeDeps {
				cfg.PluginSpecific = []*cpb.PluginSpecificConfig{
					{
						Config: &cpb.PluginSpecificConfig_RubyGem{
							RubyGem: &cpb.RubyGemConfig{
								IncludeDependencies: true,
							},
						},
					},
				}
			}
			e, err := gem.New(cfg)
			if err != nil {
				t.Fatalf("gem.New failed: %v", err)
			}

			reader := createTestGemWithMetadata(t, tt.yaml)
			res, err := e.Extract(context.Background(), &filesystem.ScanInput{
				Path:   "test.gem",
				Reader: reader,
			})

			if (err != nil) != tt.wantErr {
				t.Fatalf("Extract() err = %v, wantErr = %v", err, tt.wantErr)
			}
			if len(res.Packages) != tt.wantPkgs {
				t.Fatalf("Extract() got %d packages, want %d: %+v", len(res.Packages), tt.wantPkgs, res.Packages)
			}
			if tt.wantPkgs > 0 && tt.wantRootName != "" {
				if res.Packages[0].Name != tt.wantRootName {
					t.Errorf("res.Packages[0].Name = %q, want %q", res.Packages[0].Name, tt.wantRootName)
				}
			}
		})
	}
}
