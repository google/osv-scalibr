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

package requirements_test

import (
	"context"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
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
			name:             "requirements.txt",
			path:             "RsaCtfTool/requirements.txt",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "optional-requirements.txt",
			path:             "RsaCtfTool/optional-requirements.txt",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "requirements.in",
			path:             "RsaCtfTool/requirements.in",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "non requirements.txt txt file",
			path:         "requirements-asdf/test.txt",
			wantRequired: false,
		},
		{
			name:         "wrong extension",
			path:         "yolo-txt/requirements.md",
			wantRequired: false,
		},
		{
			name:             "requirements.txt required if file size < max file size",
			path:             "RsaCtfTool/requirements.txt",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "requirements.txt required if file size == max file size",
			path:             "RsaCtfTool/requirements.txt",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "requirements.txt not required if file size > max file size",
			path:             "RsaCtfTool/requirements.txt",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "requirements.txt required if max file size is 0",
			path:             "RsaCtfTool/requirements.txt",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = requirements.New(
				requirements.Config{
					Stats:            collector,
					MaxFileSizeBytes: tt.maxFileSizeBytes,
				},
			)

			// Set default size if not provided.
			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 100 * units.KiB
			}

			if got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			})); got != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.wantRequired)
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
		wantPackages     []*extractor.Package
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name: "no version",
			path: "testdata/no_version.txt",
			wantPackages: []*extractor.Package{
				{
					Name:     "PyCrypto",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "PyCrypto"},
				},
				{
					Name:     "GMPY2",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "GMPY2"}},
				{
					Name:     "SymPy",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "SymPy"}},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "infinite_loop",
			path: "testdata/loop.txt",
			// Makes sure we don't get stuck in an infinite loop.
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "with version",
			path: "testdata/with_versions.txt",
			wantPackages: []*extractor.Package{
				{
					Name:     "nltk",
					Version:  "3.2.2",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "nltk==3.2.2"},
				},
				{
					Name:     "tabulate",
					Version:  "0.7.7",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "tabulate==0.7.7"},
				},
				{
					Name:     "newspaper3k",
					Version:  "0.2.2",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{VersionComparator: ">=", Requirement: "newspaper3k>=0.2.2"},
				},
				{
					Name:     "asdf",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "asdf==0.7.*"},
				},
				{
					Name:     "qwerty",
					Version:  "0.1",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "qwerty   == 0.1"},
				},
				{
					Name:     "hy-phen",
					Version:  "1.2",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "hy-phen==1.2"},
				},
				{
					Name:     "under_score",
					Version:  "1.3",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "under_score==1.3"},
				},
				{
					Name:     "yolo",
					Version:  "1.0",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{VersionComparator: "===", Requirement: "yolo===1.0"},
				},
				{
					Name:     "pkg",
					Version:  "1.2.3",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{VersionComparator: "<=", Requirement: "pkg<=1.2.3"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "comments",
			path: "testdata/comments.txt",
			wantPackages: []*extractor.Package{
				{
					Name:     "PyCrypto",
					Version:  "1.2-alpha",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "PyCrypto==1.2-alpha"},
				},
				{
					Name:     "GMPY2",
					Version:  "1",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "GMPY2==1"},
				},
				{
					Name:     "SymPy",
					Version:  "1.2",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "SymPy==1.2"},
				},
				{
					Name:     "requests",
					Version:  "1.0",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "requests ==1.0"},
				},
				{
					Name:     "six",
					Version:  "1.2",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "six==1.2"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "pip example",
			path: "testdata/example.txt",
			wantPackages: []*extractor.Package{
				{
					Name:     "pytest",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "pytest"},
				},
				{
					Name:     "pytest-cov",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "pytest-cov"},
				},
				{
					Name:     "beautifulsoup4",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "beautifulsoup4"},
				},
				{
					Name:     "docopt",
					Version:  "0.6.1",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "docopt == 0.6.1"},
				},
				{
					Name:     "requests",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "requests [security] >= 2.8.1, == 2.8.* ; python_version < \"2.7\""},
				},
				// not urllib3, because it's pinned to a zip file
				{
					Name:     "keyring",
					Version:  "4.1.1",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{VersionComparator: ">=", Requirement: "keyring >= 4.1.1"},
				},
				{
					Name:     "coverage",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "coverage != 3.5"},
				},
				{
					Name:     "Mopidy-Dirble",
					Version:  "1.1",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{VersionComparator: "~=", Requirement: "Mopidy-Dirble ~= 1.1"},
				},
				{
					Name:      "transitive-req",
					Version:   "1",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/example.txt", "testdata/other-requirements.txt"},
					Metadata:  &requirements.Metadata{Requirement: "transitive-req==1"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "extras",
			path: "testdata/extras.txt",
			wantPackages: []*extractor.Package{
				{
					Name:     "pyjwt",
					Version:  "2.1.0",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "pyjwt [crypto] == 2.1.0"},
				},
				{
					Name:     "celery",
					Version:  "4.4.7",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "celery [redis, pytest] == 4.4.7"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "env variable",
			path: "testdata/env_var.txt",
			wantPackages: []*extractor.Package{
				{
					Name:     "asdf",
					Version:  "1.2",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "asdf==1.2"}},
				{
					Name:     "another",
					Version:  "1.0",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "another==1.0"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "invalid",
			path:             "testdata/invalid.txt",
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "per requirement options",
			path: "testdata/per_req_options.txt",
			wantPackages: []*extractor.Package{
				{
					// foo1==1.0 --hash=sha256:
					Name:     "foo1",
					Version:  "1.0",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"sha256:123"}, Requirement: "foo1==1.0"},
				},
				{
					// foo2==1.0 --hash=sha256:123 --global-option=foo --config-settings=bar
					Name:     "foo2",
					Version:  "1.0",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"sha256:123"}, Requirement: "foo2==1.0"},
				},
				{
					// foo3==1.0 --config-settings=bar --global-option=foo --hash=sha256:123
					Name:     "foo3",
					Version:  "1.0",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"sha256:123"}, Requirement: "foo3==1.0"},
				},
				{
					// foo4==1.0 --hash=wrongformatbutok
					Name:     "foo4",
					Version:  "1.0",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"wrongformatbutok"}, Requirement: "foo4==1.0"},
				},
				{
					// foo5==1.0; python_version < "2.7" --hash=sha256:123
					Name:     "foo5",
					Version:  "1.0",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"sha256:123"}, Requirement: "foo5==1.0; python_version < \"2.7\""},
				},
				{
					// foo6==1.0 --hash=sha256:123 unexpected_text_after_first_option_does_not_stay_around --global-option=foo
					Name:     "foo6",
					Version:  "1.0",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"sha256:123"}, Requirement: "foo6==1.0"},
				},
				{
					// foo7==1.0 unexpected_text_before_options_stays_around --hash=sha256:123
					Name:     "foo7",
					Version:  "1.0unexpected_text_before_options_stays_around",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"sha256:123"}, Requirement: "foo7==1.0 unexpected_text_before_options_stays_around"},
				},
				{
					// foo8==1.0 --hash=sha256:123 --hash=sha256:456
					Name:     "foo8",
					Version:  "1.0",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"sha256:123", "sha256:456"}, Requirement: "foo8==1.0"},
				},
				{
					// foo9==1.0 --hash=sha256:123 \
					// 	--hash=sha256:456
					Name:     "foo9",
					Version:  "1.0",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"sha256:123", "sha256:456"}, Requirement: "foo9==1.0"},
				},

				// missing a version
				// foo10== --hash=sha256:123 --hash=sha256:123

				{
					// foo11==1.0 --hash=sha256:not_base16_encoded_is_ok_;#
					Name:     "foo11",
					Version:  "1.0",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"sha256:not_base16_encoded_is_ok_;#"}, Requirement: "foo11==1.0"},
				},
				{
					// foo12==1.0 --hash=
					Name:     "foo12",
					Version:  "1.0",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "foo12==1.0"},
				},
				{
					// foo13==1.0 --hash sha256:123
					// The hash in this case is not recognized because it does not use an "=" separator
					// as specified by https://pip.pypa.io/en/stable/topics/secure-installs/#hash-checking-mode,
					// but it is dropped from the version.
					Name:     "foo13",
					Version:  "1.0",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "foo13==1.0"},
				},
				{
					// foo14=1.0 -C bar
					// short form for --config-settings flag, see https://pip.pypa.io/en/stable/cli/pip_install/#install-config-settings
					Name:     "foo14",
					Version:  "1.0",
					PURLType: purl.TypePyPi,
					Metadata: &requirements.Metadata{Requirement: "foo14==1.0"},
				},

				// Per the grammar in https://peps.python.org/pep-0508/#grammar, "--config-settings" may be
				// a valid version component, but such a string is not allowed as a version by
				// https://packaging.python.org/en/latest/specifications/version-specifiers/#version-specifiers.
				//
				// foo15== --config-settings --hash=sha256:123
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
	}

	// fill Location and Extractor
	for _, t := range tests {
		for _, p := range t.wantPackages {
			if p.Locations == nil {
				p.Locations = []string{t.path}
			}
			if p.Metadata == nil {
				p.Metadata = &requirements.Metadata{}
			}
			if p.Metadata.(*requirements.Metadata).HashCheckingModeValues == nil {
				p.Metadata.(*requirements.Metadata).HashCheckingModeValues = []string{}
			}
			if p.Version != "" && p.Metadata.(*requirements.Metadata).VersionComparator == "" {
				p.Metadata.(*requirements.Metadata).VersionComparator = "=="
			}
		}
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = requirements.New(requirements.Config{Stats: collector})

			fsys := scalibrfs.DirFS(".")

			r, err := fsys.Open(tt.path)
			defer func() {
				if err = r.Close(); err != nil {
					t.Errorf("Close(): %v", err)
				}
			}()
			if err != nil {
				t.Fatal(err)
			}

			info, err := r.Stat()
			if err != nil {
				t.Fatalf("Stat(): %v", err)
			}

			input := &filesystem.ScanInput{FS: scalibrfs.DirFS("."), Path: tt.path, Info: info, Reader: r}
			got, err := e.Extract(context.Background(), input)
			if err != nil {
				t.Fatalf("Extract(%s): %v", tt.path, err)
			}

			want := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}

			gotResultMetric := collector.FileExtractedResult(tt.path)
			if gotResultMetric != tt.wantResultMetric {
				t.Errorf("Extract(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}

			gotFileSizeMetric := collector.FileExtractedFileSize(tt.path)
			if gotFileSizeMetric != info.Size() {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", tt.path, gotFileSizeMetric, info.Size())
			}
		})
	}
}
