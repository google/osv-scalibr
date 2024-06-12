// Copyright 2024 Google LLC
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
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestFileRequired(t *testing.T) {
	var e filesystem.Extractor = requirements.Extractor{}

	tests := []struct {
		path           string
		wantIsRequired bool
	}{
		{"RsaCtfTool/requirements.txt", true},
		{"RsaCtfTool/optional-requirements.txt", true},
		{"requirements-asdf/test.txt", false},
		{"yolo-txt/requirements.md", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := e.FileRequired(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
			}); got != tt.wantIsRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.wantIsRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	var e filesystem.Extractor = requirements.Extractor{}

	tests := []struct {
		name          string
		path          string
		wantInventory []*extractor.Inventory
	}{
		{
			name:          "no version",
			path:          "testdata/no_version.txt",
			wantInventory: []*extractor.Inventory{
				// not PyCrypto, because no version pinned
				// not GMPY2, because no version pinned
				// not SymPy, because no version pinned
			},
		},
		{
			name: "with version",
			path: "testdata/with_versions.txt",
			wantInventory: []*extractor.Inventory{
				{Name: "nltk", Version: "3.2.2"},
				{Name: "tabulate", Version: "0.7.7"},
				// not newspaper3k, because it's a version range
				// not asdf, since it has a version glob
				{Name: "qwerty", Version: "0.1"},
				{Name: "hy-phen", Version: "1.2"},
				{Name: "under_score", Version: "1.3"},
				{Name: "yolo", Version: "1.0"},
			},
		},
		{
			name: "comments",
			path: "testdata/comments.txt",
			wantInventory: []*extractor.Inventory{
				{Name: "PyCrypto", Version: "1.2-alpha"},
				{Name: "GMPY2", Version: "1"},
				{Name: "SymPy", Version: "1.2"},
				{Name: "requests", Version: "1.0"},
				{Name: "six", Version: "1.2"},
			},
		},
		{
			name: "pip example",
			path: "testdata/example.txt",
			wantInventory: []*extractor.Inventory{
				// not pytest, because no version
				// not pytest-cov, because no version
				// not beautifulsoup4, because no version
				{Name: "docopt", Version: "0.6.1"},
				// not requests, because it has extras
				// not urllib3, because it's pinned to a zip file
			},
		},
		{
			name: "extras",
			path: "testdata/extras.txt",
			wantInventory: []*extractor.Inventory{
				{Name: "pyjwt", Version: "2.1.0"},
				{Name: "celery", Version: "4.4.7"},
			},
		},
		{
			name: "env variable",
			path: "testdata/env_var.txt",
			wantInventory: []*extractor.Inventory{
				{Name: "asdf", Version: "1.2"},
				{Name: "another", Version: "1.0"},
			},
		},
		{
			name:          "invalid",
			path:          "testdata/invalid.txt",
			wantInventory: []*extractor.Inventory{},
		},
		{
			name: "per requirement options",
			path: "testdata/per_req_options.txt",
			wantInventory: []*extractor.Inventory{
				{
					// foo1==1.0 --hash=sha256:123
					Name:     "foo1",
					Version:  "1.0",
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"sha256:123"}},
				},
				{
					// foo2==1.0 --hash=sha256:123 --global-option=foo --config-settings=bar
					Name:     "foo2",
					Version:  "1.0",
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"sha256:123"}},
				},
				{
					// foo3==1.0 --config-settings=bar --global-option=foo --hash=sha256:123
					Name:     "foo3",
					Version:  "1.0",
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"sha256:123"}},
				},
				{
					// foo4==1.0 --hash=wrongformatbutok
					Name:     "foo4",
					Version:  "1.0",
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"wrongformatbutok"}},
				},
				{
					// foo5==1.0; python_version < "2.7" --hash=sha256:123
					Name:     "foo5",
					Version:  "1.0",
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"sha256:123"}},
				},
				{
					// foo6==1.0 --hash=sha256:123 unexpected_text_after_first_option_does_not_stay_around --global-option=foo
					Name:     "foo6",
					Version:  "1.0",
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"sha256:123"}},
				},
				{
					// foo7==1.0 unexpected_text_before_options_stays_around --hash=sha256:123
					Name:     "foo7",
					Version:  "1.0unexpected_text_before_options_stays_around",
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"sha256:123"}},
				},
				{
					// foo8==1.0 --hash=sha256:123 --hash=sha256:456
					Name:     "foo8",
					Version:  "1.0",
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"sha256:123", "sha256:456"}},
				},
				{
					// foo9==1.0 --hash=sha256:123 \
					// 	--hash=sha256:456
					Name:     "foo9",
					Version:  "1.0",
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"sha256:123", "sha256:456"}},
				},

				// missing a version
				// foo10== --hash=sha256:123 --hash=sha256:123

				{
					// foo11==1.0 --hash=sha256:not_base16_encoded_is_ok_;#
					Name:     "foo11",
					Version:  "1.0",
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{"sha256:not_base16_encoded_is_ok_;#"}},
				},
				{
					// foo12==1.0 --hash=
					Name:    "foo12",
					Version: "1.0",
				},
				{
					// foo13==1.0 --hash sha256:123
					// The hash in this case is not recognized because it does not use an "=" separator
					// as specified by https://pip.pypa.io/en/stable/topics/secure-installs/#hash-checking-mode,
					// but it is dropped from the version.
					Name:    "foo13",
					Version: "1.0",
				},
				{
					// foo14=1.0 -C bar
					// short form for --config-settings flag, see https://pip.pypa.io/en/stable/cli/pip_install/#install-config-settings
					Name:    "foo14",
					Version: "1.0",
				},

				// Per the grammar in https://peps.python.org/pep-0508/#grammar, "--config-settings" may be
				// a valid version component, but such a string is not allowed as a version by
				// https://packaging.python.org/en/latest/specifications/version-specifiers/#version-specifiers.
				//
				// foo15== --config-settings --hash=sha256:123
			},
		},
	}

	// fill Location and Extractor
	for _, t := range tests {
		for _, i := range t.wantInventory {
			i.Locations = []string{t.path}
		}
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			fsys := os.DirFS(".")

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

			input := &filesystem.ScanInput{Path: tt.path, Info: info, Reader: r}
			got, err := e.Extract(context.Background(), input)
			if err != nil {
				t.Fatalf("Extract(%s): %v", tt.path, err)
			}

			want := tt.wantInventory
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	e := requirements.Extractor{}
	i := &extractor.Inventory{
		Name:      "Name",
		Version:   "1.2.3",
		Locations: []string{"location"},
		Metadata:  &requirements.Metadata{HashCheckingModeValues: []string{"sha256:123xyz"}},
	}
	want := &purl.PackageURL{
		Type:    purl.TypePyPi,
		Name:    "name",
		Version: "1.2.3",
	}
	got, err := e.ToPURL(i)
	if err != nil {
		t.Fatalf("ToPURL(%v): %v", i, err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ToPURL(%v) (-want +got):\n%s", i, diff)
	}
}
