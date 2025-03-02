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

package wheelegg_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
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
			name:             ".dist-info/METADATA",
			path:             "testdata/pip-22.2.2.dist-info/METADATA",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             ".egg/EGG-INFO/PKG-INFO",
			path:             "testdata/setuptools-57.4.0-py3.9.egg/EGG-INFO/PKG-INFO",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             ".egg-info",
			path:             "testdata/pycups-2.0.1.egg-info",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             ".egg-info/PKG-INFO",
			path:             "testdata/httplib2-0.20.4.egg-info/PKG-INFO",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         ".dist-info/TEST",
			path:         "testdata/pip-22.2.2.dist-info/TEST",
			wantRequired: false,
		},
		{
			name:             ".egg",
			path:             "python3.10/site-packages/monotonic-1.6-py3.10.egg",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             ".egg-info required if size less than maxFileSizeBytes",
			path:             "testdata/pycups-2.0.1.egg-info",
			maxFileSizeBytes: 1000,
			fileSizeBytes:    100,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             ".egg required if size equal to maxFileSizeBytes",
			path:             "python3.10/site-packages/monotonic-1.6-py3.10.egg",
			maxFileSizeBytes: 1000,
			fileSizeBytes:    1000,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             ".egg not required if size greater than maxFileSizeBytes",
			path:             "python3.10/site-packages/monotonic-1.6-py3.10.egg",
			maxFileSizeBytes: 100,
			fileSizeBytes:    1000,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             ".egg required if maxFileSizeBytes explicitly set to 0",
			path:             "python3.10/site-packages/monotonic-1.6-py3.10.egg",
			maxFileSizeBytes: 0,
			fileSizeBytes:    1000,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e := wheelegg.New(wheelegg.Config{
				MaxFileSizeBytes: tt.maxFileSizeBytes,
				Stats:            collector,
			})

			// Set a default file size if not specified.
			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1000
			}

			if got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			})); got != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.wantRequired)
			}

			gotResultMetric := collector.FileRequiredResult(tt.path)
			if tt.wantResultMetric != "" && gotResultMetric != tt.wantResultMetric {
				t.Errorf("FileRequired(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		cfg              wheelegg.Config
		wantInventory    []*extractor.Inventory
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name: ".dist-info/METADATA",
			path: "testdata/distinfo_meta",
			wantInventory: []*extractor.Inventory{{
				Name:      "pip",
				Version:   "22.2.2",
				Locations: []string{"testdata/distinfo_meta"},
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
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
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

			collector := testcollector.New()
			tt.cfg.Stats = collector

			input := &filesystem.ScanInput{FS: scalibrfs.DirFS("."), Path: tt.path, Info: info, Reader: r}
			e := wheelegg.New(defaultConfigWith(tt.cfg))
			got, err := e.Extract(t.Context(), input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.name, err, tt.wantErr)
			}

			want := tt.wantInventory
			if diff := cmp.Diff(want, got); diff != "" {
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

// defaultConfigWith combines any non-zero fields of cfg with wheelegg.DefaultConfig().
func defaultConfigWith(cfg wheelegg.Config) wheelegg.Config {
	newCfg := wheelegg.DefaultConfig()

	if cfg.MaxFileSizeBytes > 0 {
		newCfg.MaxFileSizeBytes = cfg.MaxFileSizeBytes
	}
	if cfg.Stats != nil {
		newCfg.Stats = cfg.Stats
	}
	return newCfg
}

func TestExtractWithoutReadAt(t *testing.T) {
	var e filesystem.Extractor = wheelegg.New(wheelegg.DefaultConfig())

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

			input := &filesystem.ScanInput{FS: scalibrfs.DirFS("."), Path: tt.path, Info: info, Reader: noReadAt}
			got, err := e.Extract(t.Context(), input)
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

func TestExtractErrorsWithFakeFiles(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		fakeFileInfo     fs.FileInfo
		fakeFileBytes    []byte
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name: "invalid zip file",
			path: "testdata/does_not_exist.egg",
			fakeFileInfo: fakefs.FakeFileInfo{
				FileName: "does_not_exist.egg",
				FileMode: fs.ModePerm,
				FileSize: 1000,
			},
			fakeFileBytes:    []byte("invalid zip file"),
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := tt.fakeFileInfo
			r := bytes.NewReader(tt.fakeFileBytes)

			collector := testcollector.New()
			cfg := wheelegg.Config{Stats: collector}

			input := &filesystem.ScanInput{FS: scalibrfs.DirFS("."), Path: tt.path, Info: info, Reader: r}
			e := wheelegg.New(defaultConfigWith(cfg))
			_, err := e.Extract(t.Context(), input)
			if err == nil {
				t.Fatalf("Extract(%+v) succeeded, want error: %v", tt.name, tt.wantErr)
			}
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v", tt.name, err, tt.wantErr)
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
	fsys := scalibrfs.DirFS(".")
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

	input := &filesystem.ScanInput{FS: scalibrfs.DirFS("."), Path: path, Info: info, Reader: r}
	e := wheelegg.Extractor{}
	_, gotErr := e.Extract(t.Context(), input)
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
	got := e.ToPURL(i)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ToPURL(%v) (-want +got):\n%s", i, diff)
	}
}
