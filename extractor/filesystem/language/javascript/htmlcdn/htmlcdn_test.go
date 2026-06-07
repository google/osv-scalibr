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

package htmlcdn_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/htmlcdn"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
		wantResultMetric stats.FileRequiredResult
	}{
		{
			name:             "HTML file at root",
			path:             "index.html",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "HTM file",
			path:             "filetypes/index.htm",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "HTM file (with caps)",
			path:             "filetypes/CAPS.HTM",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "GO Template",
			path:             "filetypes/index.gohtml",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "GO Template 2",
			path:             "filetypes/index.tmpl",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "GO Template 3",
			path:             "filetypes/index.tpl",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "Jinja Template",
			path:             "filetypes/index.jinja",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "Jinja Template",
			path:             "filetypes/index.jinja2",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "Jinja Template",
			path:             "filetypes/index.j2",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "PHP page",
			path:             "filetypes/index.php",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "Razor Template",
			path:             "filetypes/index.razor",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "Razor Template 2",
			path:             "filetypes/index.cshtml",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "ASP page",
			path:             "filetypes/index.asp",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "ASPX page",
			path:             "filetypes/index.aspx",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "ASCX page",
			path:             "filetypes/index.ascx",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "Master page",
			path:             "filetypes/index.master",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "JSP page",
			path:             "filetypes/index.jsp",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "JSP page 2",
			path:             "filetypes/index.jspx",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "JSP page 3",
			path:             "filetypes/index.jspf",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "not an HTML file",
			path:         "testdata/test.js",
			wantRequired: false,
		},
		{
			name:             "HTML file required if size less than maxFileSizeBytes",
			path:             "index.html",
			fileSizeBytes:    1000 * units.MiB,
			maxFileSizeBytes: 2000 * units.MiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "HTML file required if size equal to maxFileSizeBytes",
			path:             "index.html",
			fileSizeBytes:    1000 * units.MiB,
			maxFileSizeBytes: 1000 * units.MiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "HTML file not required if size greater than maxFileSizeBytes",
			path:             "index.html",
			fileSizeBytes:    10000 * units.MiB,
			maxFileSizeBytes: 1000 * units.MiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "HTML file required if maxFileSizeBytes explicitly set to 0",
			path:             "index.html",
			fileSizeBytes:    1000 * units.MiB,
			maxFileSizeBytes: 0,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := htmlcdn.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("htmlcdn.New: %v", err)
			}
			e.(*htmlcdn.Extractor).Stats = collector

			// Set a default file size if not specified.
			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1 * units.KiB
			}

			isRequired := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
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

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		includeDeps      bool
		wantPackages     []*extractor.Package
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		// Generic tests
		{
			name: "CDN URL with HTTP scheme",
			path: "testdata/http_scheme.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "jsdelivr",
					Version:  "1.1.1",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/http_scheme.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.1.1", FullURL: "http://cdn.jsdelivr.net/npm/jsdelivr@1.1.1"},
				},
				{
					Name:     "unpkg",
					Version:  "2.2.2",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/http_scheme.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "2.2.2", FullURL: "http://unpkg.com/unpkg@2.2.2"},
				},
			},
		},
		{
			name: "CDN URL with upper case script tag",
			path: "testdata/upper_case_script.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "jsdelivr",
					Version:  "1.1.1",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/upper_case_script.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.1.1", FullURL: "https://cdn.jsdelivr.net/npm/jsdelivr@1.1.1"},
				},
				{
					Name:     "unpkg",
					Version:  "2.2.2",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/upper_case_script.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "2.2.2", FullURL: "https://unpkg.com/unpkg@2.2.2"},
				},
			},
		},
		{
			name: "Ignore invalid CDN URLs",
			path: "testdata/miss.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "should-be-the-only-package",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/miss.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "0.0.0", FullURL: "https://cdn.jsdelivr.net/npm/should-be-the-only-package@0.0.0/index.js"},
				},
			},
		},
		{
			name: "Parse deeply nested script links",
			path: "testdata/deeply_nested.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "a",
					Version:  "1.2.3",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/deeply_nested.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.2.3", FullURL: "https://cdn.jsdelivr.net/npm/a@1.2.3/index.js"},
				},
				{
					Name:     "b",
					Version:  "4.5.6",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/deeply_nested.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "4.5.6", FullURL: "https://cdn.jsdelivr.net/npm/b@4.5.6/index.js"},
				},
			},
		},
		{
			name: "Malformed script tags skipped",
			path: "testdata/malformed_script.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "a",
					Version:  "1.2.3",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/malformed_script.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.2.3", FullURL: "https://cdn.jsdelivr.net/npm/a@1.2.3/index.js"},
				},
			},
		},
		{
			name: "Test depth limit doesnt exist",
			path: "testdata/512.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "a",
					Version:  "1.2.3",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/512.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.2.3", FullURL: "https://cdn.jsdelivr.net/npm/a@1.2.3"},
				},
				{
					Name:     "b",
					Version:  "4.5.6",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/512.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "4.5.6", FullURL: "https://cdn.jsdelivr.net/npm/b@4.5.6"},
				},
			},
		},
		// jsDelivr specific tests
		{
			name: "jsDelivr CDN URL with explicit version and file",
			path: "testdata/jsdelivr/with_file.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "cookie-parser",
					Version:  "1.4.4",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/jsdelivr/with_file.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.4.4", FullURL: "https://cdn.jsdelivr.net/npm/cookie-parser@1.4.4/index.js"},
				},
			},
		},
		{
			name: "jsDelivr CDN URL with explicit version and no file",
			path: "testdata/jsdelivr/without_file.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "cookie-parser",
					Version:  "1.4.4",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/jsdelivr/without_file.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.4.4", FullURL: "https://cdn.jsdelivr.net/npm/cookie-parser@1.4.4"},
				},
			},
		},
		{
			name: "Test jsDelivr explicit/implicit latest",
			path: "testdata/jsdelivr/latest.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "a",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/jsdelivr/latest.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "latest", FullURL: "https://cdn.jsdelivr.net/npm/a@latest"},
				},
				{
					Name:     "b",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/jsdelivr/latest.html"),
					Metadata: &htmlcdn.Metadata{FullURL: "https://cdn.jsdelivr.net/npm/b/index.js"},
				},
				{
					Name:     "c",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/jsdelivr/latest.html"),
					Metadata: &htmlcdn.Metadata{FullURL: "https://cdn.jsdelivr.net/npm/c"},
				},
			},
		},
		{
			name: "jsDelivr based SemVer versions",
			path: "testdata/jsdelivr/semver.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "cookie-parser",
					Version:  "1.4.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/jsdelivr/semver.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.4", FullURL: "https://cdn.jsdelivr.net/npm/cookie-parser@1.4"},
				},
				{
					Name:     "cookie-parser",
					Version:  "1.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/jsdelivr/semver.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1", FullURL: "https://cdn.jsdelivr.net/npm/cookie-parser@1"},
				},
			},
		},
		{
			name: "jsDelivr user packages",
			path: "testdata/jsdelivr/user_package.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "@vue/runtime-dom",
					Version:  "3.5.35",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/jsdelivr/user_package.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "3.5.35", FullURL: "https://cdn.jsdelivr.net/npm/@vue/runtime-dom@3.5.35/index.js"},
				},
				{
					Name:     "@vue/runtime-dom",
					Version:  "3.5.35",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/jsdelivr/user_package.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "3.5.35", FullURL: "https://cdn.jsdelivr.net/npm/@vue/runtime-dom@3.5.35"},
				},
				{
					Name:     "@vue/runtime-dom",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/jsdelivr/user_package.html"),
					Metadata: &htmlcdn.Metadata{FullURL: "https://cdn.jsdelivr.net/npm/@vue/runtime-dom/index.js"},
				},
				{
					Name:     "@vue/runtime-dom",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/jsdelivr/user_package.html"),
					Metadata: &htmlcdn.Metadata{FullURL: "https://cdn.jsdelivr.net/npm/@vue/runtime-dom"},
				},
				{
					Name:     "@u/p",
					Version:  "1.2.3",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/jsdelivr/user_package.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.2.3", FullURL: "https://cdn.jsdelivr.net/npm/@u/p@1.2.3/index.js"},
				},
				{
					Name:     "@u/p",
					Version:  "1.2.3",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/jsdelivr/user_package.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.2.3", FullURL: "https://cdn.jsdelivr.net/npm/@u/p@1.2.3"},
				},
				{
					Name:     "@u/p",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/jsdelivr/user_package.html"),
					Metadata: &htmlcdn.Metadata{FullURL: "https://cdn.jsdelivr.net/npm/@u/p/index.js"},
				},
				{
					Name:     "@u/p",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/jsdelivr/user_package.html"),
					Metadata: &htmlcdn.Metadata{FullURL: "https://cdn.jsdelivr.net/npm/@u/p"},
				},
			},
		},
		// UNPKG specific tests
		{
			name: "Test UNPKG explicit/implicit latest",
			path: "testdata/unpkg/latest.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "a",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/latest.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "latest", FullURL: "https://unpkg.com/a@latest"},
				},
				{
					Name:     "b",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/latest.html"),
					Metadata: &htmlcdn.Metadata{FullURL: "https://unpkg.com/b/index.js"},
				},
				{
					Name:     "c",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/latest.html"),
					Metadata: &htmlcdn.Metadata{FullURL: "https://unpkg.com/c"},
				},
			},
		},
		{
			name: "UNPKG CDN URL with explicit version and file",
			path: "testdata/unpkg/with_file.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "cookie-parser",
					Version:  "1.4.4",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/with_file.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.4.4", FullURL: "https://unpkg.com/cookie-parser@1.4.4/index.js"},
				},
			},
		},
		{
			name: "UNPKG CDN URL with explicit version and no file",
			path: "testdata/unpkg/without_file.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "cookie-parser",
					Version:  "1.4.4",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/without_file.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.4.4", FullURL: "https://unpkg.com/cookie-parser@1.4.4"},
				},
			},
		},
		{
			name: "UNPKG based SemVer versions",
			path: "testdata/unpkg/semver.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "cookie-parser",
					Version:  "1.4.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/semver.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.4", FullURL: "https://unpkg.com/cookie-parser@1.4"},
				},
				{
					Name:     "cookie-parser",
					Version:  "1.4.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/semver.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.4.x", FullURL: "https://unpkg.com/cookie-parser@1.4.x"},
				},
				{
					Name:     "cookie-parser",
					Version:  "1.4.4",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/semver.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "~1.4.4", FullURL: "https://unpkg.com/cookie-parser@~1.4.4"},
				},
				{
					Name:     "cookie-parser",
					Version:  "1.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/semver.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1", FullURL: "https://unpkg.com/cookie-parser@1"},
				},
				{
					Name:     "cookie-parser",
					Version:  "1.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/semver.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.x", FullURL: "https://unpkg.com/cookie-parser@1.x"},
				},
				{
					Name:     "cookie-parser",
					Version:  "1.4.4",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/semver.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "^1.4.4", FullURL: "https://unpkg.com/cookie-parser@%5E1.4.4"},
				},
				{
					Name:     "cookie-parser",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/semver.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "*", FullURL: "https://unpkg.com/cookie-parser@*"},
				},
				{
					Name:     "cookie-parser",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/semver.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "x", FullURL: "https://unpkg.com/cookie-parser@x"},
				},
				{
					Name:     "cookie-parser",
					Version:  "1.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/semver.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.0.0 - 1.4.3", FullURL: "https://unpkg.com/cookie-parser@1.0.0%20-%201.4.3"},
				},
				{
					Name:     "cookie-parser",
					Version:  "1.4.5",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/semver.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: ">1.4.4", FullURL: "https://unpkg.com/cookie-parser@%3E1.4.4"},
				},
			},
		},
		{
			name: "UNPKG ESM support",
			path: "testdata/unpkg/esm.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "cookie-parser",
					Version:  "1.4.4",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/esm.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.4.4", FullURL: "https://esm.unpkg.com/cookie-parser@1.4.4"},
				},
				{
					Name:     "cookie-parser",
					Version:  "1.4.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/esm.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.4", FullURL: "https://esm.unpkg.com/cookie-parser@1.4"},
				},
				{
					Name:     "cookie-parser",
					Version:  "1.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/esm.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1", FullURL: "https://esm.unpkg.com/cookie-parser@1"},
				},
				{
					Name:     "cookie-parser",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/esm.html"),
					Metadata: &htmlcdn.Metadata{FullURL: "https://esm.unpkg.com/cookie-parser"},
				},
			},
		},
		{
			name: "UNPKG user packages",
			path: "testdata/unpkg/user_package.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "@vue/runtime-dom",
					Version:  "3.5.35",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/user_package.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "3.5.35", FullURL: "https://unpkg.com/@vue/runtime-dom@3.5.35/index.js"},
				},
				{
					Name:     "@vue/runtime-dom",
					Version:  "3.5.35",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/user_package.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "3.5.35", FullURL: "https://unpkg.com/@vue/runtime-dom@3.5.35"},
				},
				{
					Name:     "@vue/runtime-dom",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/user_package.html"),
					Metadata: &htmlcdn.Metadata{FullURL: "https://unpkg.com/@vue/runtime-dom/index.js"},
				},
				{
					Name:     "@vue/runtime-dom",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/user_package.html"),
					Metadata: &htmlcdn.Metadata{FullURL: "https://unpkg.com/@vue/runtime-dom"},
				},
				{
					Name:     "@u/p",
					Version:  "1.2.3",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/user_package.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.2.3", FullURL: "https://unpkg.com/@u/p@1.2.3/index.js"},
				},
				{
					Name:     "@u/p",
					Version:  "1.2.3",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/user_package.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "1.2.3", FullURL: "https://unpkg.com/@u/p@1.2.3"},
				},
				{
					Name:     "@u/p",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/user_package.html"),
					Metadata: &htmlcdn.Metadata{FullURL: "https://unpkg.com/@u/p/index.js"},
				},
				{
					Name:     "@u/p",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/unpkg/user_package.html"),
					Metadata: &htmlcdn.Metadata{FullURL: "https://unpkg.com/@u/p"},
				},
			},
		},
		// esm.run specific tests
		{
			name: "esm.run CDN URL with explicit version and file",
			path: "testdata/esmrun/with_file.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "d3",
					Version:  "7.8.3",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/esmrun/with_file.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "7.8.3", FullURL: "https://esm.run/d3@7.8.3/dist/d3.js"},
				},
			},
		},
		{
			name: "esm.run CDN URL with explicit version and no file",
			path: "testdata/esmrun/without_file.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "d3",
					Version:  "7.8.3",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/esmrun/without_file.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "7.8.3", FullURL: "https://esm.run/d3@7.8.3"},
				},
			},
		},
		{
			name: "Test esm.run explicit/implicit latest",
			path: "testdata/esmrun/latest.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "a",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/esmrun/latest.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "latest", FullURL: "https://esm.run/a@latest"},
				},
				{
					Name:     "b",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/esmrun/latest.html"),
					Metadata: &htmlcdn.Metadata{FullURL: "https://esm.run/b/index.js"},
				},
				{
					Name:     "c",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/esmrun/latest.html"),
					Metadata: &htmlcdn.Metadata{FullURL: "https://esm.run/c"},
				},
			},
		},
		// Importmap specific tests
		{
			name: "Importmap support",
			path: "testdata/importmap.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "jsdelivr-imports",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/importmap.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "0.0.0", FullURL: "https://cdn.jsdelivr.net/npm/jsdelivr-imports@0.0.0"},
				},
				{
					Name:     "unpkg-imports",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/importmap.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "0.0.0", FullURL: "https://unpkg.com/unpkg-imports@0.0.0"},
				},
				{
					Name:     "esm-unpkg-imports",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/importmap.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "0.0.0", FullURL: "https://esm.unpkg.com/esm-unpkg-imports@0.0.0"},
				},
				{
					Name:     "esm-run-imports",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/importmap.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "0.0.0", FullURL: "https://esm.run/esm-run-imports@0.0.0"},
				},
				{
					Name:     "jsdelivr-scopes",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/importmap.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "0.0.0", FullURL: "https://cdn.jsdelivr.net/npm/jsdelivr-scopes@0.0.0"},
				},
				{
					Name:     "unpkg-scopes",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/importmap.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "0.0.0", FullURL: "https://unpkg.com/unpkg-scopes@0.0.0"},
				},
				{
					Name:     "esm-unpkg-scopes",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/importmap.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "0.0.0", FullURL: "https://esm.unpkg.com/esm-unpkg-scopes@0.0.0"},
				},
				{
					Name:     "esm-run-scopes",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/importmap.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "0.0.0", FullURL: "https://esm.run/esm-run-scopes@0.0.0"},
				},
				{
					Name:     "imports-only",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/importmap.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "0.0.0", FullURL: "https://cdn.jsdelivr.net/npm/imports-only@0.0.0"},
				},
				{
					Name:     "scopes-only",
					Version:  "0.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/importmap.html"),
					Metadata: &htmlcdn.Metadata{RawVersion: "0.0.0", FullURL: "https://cdn.jsdelivr.net/npm/scopes-only@0.0.0"},
				},
			},
		},
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			r, err := os.Open(tt.path)
			defer func() {
				if err = r.Close(); err != nil {
					t.Errorf("Close(): %v", err)
				}
			}()
			if err != nil {
				t.Fatal(err)
			}

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
					{Config: &cpb.PluginSpecificConfig_JavascriptPackageJson{
						JavascriptPackageJson: &cpb.JavascriptPackageJsonConfig{
							IncludeDependencies: tt.includeDeps,
						},
					}},
				},
			}
			e, err := htmlcdn.New(cfg)
			if err != nil {
				t.Fatalf("htmlcdn.New: %v", err)
			}
			e.(*htmlcdn.Extractor).Stats = collector
			got, err := e.Extract(t.Context(), input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.name, err, tt.wantErr)
			}

			var want inventory.Inventory
			if tt.wantPackages != nil {
				want = inventory.Inventory{Packages: tt.wantPackages}
			}

			if diff := cmp.Diff(want, got, cmpopts.SortSlices(extracttest.PackageCmpLess), cmpopts.EquateEmpty()); diff != "" {
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
