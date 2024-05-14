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

package wheelegg_test

import (
	"context"
	"io/fs"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	extractor "github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/purl"
)

func TestFileRequired(t *testing.T) {
	var e extractor.InventoryExtractor = wheelegg.Extractor{}

	tests := []struct {
		name           string
		path           string
		wantIsRequired bool
	}{
		{
			name:           ".dist-info/METADATA",
			path:           "testdata/pip-22.2.2.dist-info/METADATA",
			wantIsRequired: true,
		},
		{
			name:           ".egg/EGG-INFO/PKG-INFO",
			path:           "testdata/setuptools-57.4.0-py3.9.egg/EGG-INFO/PKG-INFO",
			wantIsRequired: true,
		},
		{
			name:           ".egg-info",
			path:           "testdata/pycups-2.0.1.egg-info",
			wantIsRequired: true,
		},
		{
			name:           ".egg-info/PKG-INFO",
			path:           "testdata/httplib2-0.20.4.egg-info/PKG-INFO",
			wantIsRequired: true,
		},
		{
			name:           ".dist-info/TEST",
			path:           "testdata/pip-22.2.2.dist-info/TEST",
			wantIsRequired: false,
		},
		{
			name:           ".egg",
			path:           "python3.10/site-packages/monotonic-1.6-py3.10.egg",
			wantIsRequired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := e.FileRequired(tt.path, 0); got != tt.wantIsRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.wantIsRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		cfg           wheelegg.Config
		wantInventory []*extractor.Inventory
		wantErr       error
	}{
		{
			name: ".dist-info/METADATA",
			path: "testdata/distinfo_meta",
			wantInventory: []*extractor.Inventory{{
				Name:      "pip",
				Version:   "22.2.2",
				Locations: []string{"testdata/distinfo_meta"},
				Extractor: wheelegg.Name,
				Metadata: &wheelegg.PythonPackageMetadata{
					Author:      "The pip developers",
					AuthorEmail: "distutils-sig@python.org",
				},
			}},
		},
		{
			name: ".egg/EGG-INFO/PKG-INFO",
			path: "testdata/egginfo_pkginfo",
			wantInventory: []*extractor.Inventory{{
				Name:      "setuptools",
				Version:   "57.4.0",
				Locations: []string{"testdata/egginfo_pkginfo"},
				Extractor: wheelegg.Name,
				Metadata: &wheelegg.PythonPackageMetadata{
					Author:      "Python Packaging Authority",
					AuthorEmail: "distutils-sig@python.org",
				},
			}},
		},
		{
			name: ".egg-info",
			path: "testdata/egginfo",
			wantInventory: []*extractor.Inventory{{
				Name:      "pycups",
				Version:   "2.0.1",
				Locations: []string{"testdata/egginfo"},
				Extractor: wheelegg.Name,
				Metadata: &wheelegg.PythonPackageMetadata{
					Author:      "Zdenek Dohnal",
					AuthorEmail: "zdohnal@redhat.com",
				},
			}},
		},
		{
			name: ".egg-info/PKG-INFO",
			path: "testdata/pkginfo",
			wantInventory: []*extractor.Inventory{{
				Name:      "httplib2",
				Version:   "0.20.4",
				Locations: []string{"testdata/pkginfo"},
				Extractor: wheelegg.Name,
				Metadata: &wheelegg.PythonPackageMetadata{
					Author:      "Joe Gregorio",
					AuthorEmail: "joe@bitworking.org",
				},
			},
			},
		},
		{
			name: "malformed PKG-INFO",
			path: "testdata/malformed_pkginfo",
			wantInventory: []*extractor.Inventory{{
				Name:      "passlib",
				Version:   "1.7.4",
				Locations: []string{"testdata/malformed_pkginfo"},
				Extractor: wheelegg.Name,
				Metadata: &wheelegg.PythonPackageMetadata{
					Author:      "Eli Collins",
					AuthorEmail: "elic@assurancetechnologies.com",
				},
			}},
		},
		{
			name: ".egg",
			path: "testdata/monotonic-1.6-py3.10.egg",
			wantInventory: []*extractor.Inventory{{
				Name:      "monotonic",
				Version:   "1.6",
				Locations: []string{"testdata/monotonic-1.6-py3.10.egg"},
				Extractor: wheelegg.Name,
				Metadata: &wheelegg.PythonPackageMetadata{
					Author:      "Ori Livneh",
					AuthorEmail: "ori@wikimedia.org",
				},
			}},
		},
		{
			name:          ".egg without PKG-INFO",
			path:          "testdata/monotonic_no_pkginfo-1.6-py3.10.egg",
			wantInventory: []*extractor.Inventory{},
		},
		{
			name: "file size over limit",
			path: "testdata/distinfo_meta",
			cfg: wheelegg.Config{
				MaxFileSize: 5,
			},
			wantErr: cmpopts.AnyError,
		},
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

			input := &extractor.ScanInput{Path: tt.path, Info: info, Reader: r}
			e := wheelegg.New(defaultConfigWith(tt.cfg))
			got, err := e.Extract(context.Background(), input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.name, err, tt.wantErr)
			}

			want := tt.wantInventory
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}

// defaultConfigWith combines any non-zero fields of cfg with wheelegg.DefaultConfig().
func defaultConfigWith(cfg wheelegg.Config) wheelegg.Config {
	newCfg := wheelegg.DefaultConfig()

	if cfg.MaxFileSize > 0 {
		newCfg.MaxFileSize = cfg.MaxFileSize
	}
	return newCfg
}

func TestExtractWithoutReadAt(t *testing.T) {
	var e extractor.InventoryExtractor = wheelegg.New(wheelegg.DefaultConfig())

	tests := []struct {
		name          string
		path          string
		wantInventory *extractor.Inventory
	}{
		{
			name: ".egg",
			path: "testdata/monotonic-1.6-py3.10.egg",
			wantInventory: &extractor.Inventory{
				Name:      "monotonic",
				Version:   "1.6",
				Locations: []string{"testdata/monotonic-1.6-py3.10.egg"},
				Extractor: e.Name(),
				Metadata: &wheelegg.PythonPackageMetadata{
					Author:      "Ori Livneh",
					AuthorEmail: "ori@wikimedia.org",
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

			noReadAt := reader{r}

			info, err := noReadAt.Stat()
			if err != nil {
				t.Fatalf("Stat(): %v", err)
			}

			input := &extractor.ScanInput{Path: tt.path, Info: info, Reader: noReadAt}
			got, err := e.Extract(context.Background(), input)
			if err != nil {
				t.Fatalf("Extract(%s): %v", tt.path, err)
			}

			want := []*extractor.Inventory{tt.wantInventory}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}

type reader struct {
	f fs.File
}

func (r reader) Read(p []byte) (n int, err error) {
	return r.f.Read(p)
}

func (r reader) Stat() (fs.FileInfo, error) {
	return r.f.Stat()
}

func TestExtractEggWithoutSize(t *testing.T) {
	fsys := os.DirFS(".")
	path := "testdata/monotonic-1.6-py3.10.egg"

	r, err := fsys.Open(path)
	defer func() {
		if err = r.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	}()
	if err != nil {
		t.Fatal(err)
	}

	// Set FileInfo to nil, which does not allow input.info.Size(). This is required for unzipping the
	// egg file.
	var info fs.FileInfo = nil

	input := &extractor.ScanInput{Path: path, Info: info, Reader: r}
	e := wheelegg.Extractor{}
	_, gotErr := e.Extract(context.Background(), input)
	wantErr := wheelegg.ErrSizeNotSet
	if gotErr != wantErr {
		t.Fatalf("Extract(%s) got err: '%v', want err: '%v'", path, gotErr, wantErr)
	}
}

func TestToPURL(t *testing.T) {
	e := wheelegg.Extractor{}
	i := &extractor.Inventory{
		Name:      "Name",
		Version:   "1.2.3",
		Locations: []string{"location"},
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
