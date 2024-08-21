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

package osv_test

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

func TestName(t *testing.T) {
	w := osv.Wrapper{
		ExtractorName:    "testname",
		ExtractorVersion: 123,
		Extractor:        MockExtractor{},
		PURLType:         purl.TypeDebian,
	}

	if w.Name() != "testname" {
		t.Errorf("Name() = %q, want %q", w.Name(), "testname")
	}
}

func TestVersion(t *testing.T) {
	w := osv.Wrapper{
		ExtractorName:    "testname",
		ExtractorVersion: 123,
		Extractor:        MockExtractor{},
		PURLType:         purl.TypeDebian,
	}

	if w.Version() != 123 {
		t.Errorf("Version() = %d, want %d", w.Version(), 123)
	}
}

func TestFileRequired(t *testing.T) {

	tests := []struct {
		name             string
		path             string
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
		wantResultMetric stats.FileRequiredResult
	}{
		// Basic filename matches.
		{path: "match.json", wantRequired: true, wantResultMetric: stats.FileRequiredResultOK},
		{path: "foo", wantRequired: false},
		{path: "", wantRequired: false},
		// File size limits.
		{
			name:             "file is required if file size < max file size",
			path:             "match.json",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "file is required if file size = max file size",
			path:             "match.json",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "file not required if file size > max file size",
			path:             "match.json",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "file is required if max file size set to 0",
			path:             "match.json",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		name := tt.name
		if name == "" {
			name = tt.path
		}

		t.Run(name, func(t *testing.T) {
			collector := testcollector.New()
			w := osv.Wrapper{
				ExtractorName:    "testname",
				ExtractorVersion: 123,
				Extractor:        MockExtractor{},
				PURLType:         purl.TypeDebian,
				Stats:            collector,
				MaxFileSizeBytes: tt.maxFileSizeBytes,
			}

			// Set default size if not provided.
			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 100 * units.KiB
			}

			isRequired := w.FileRequired(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			})
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

var (
	errTestMock = fmt.Errorf("test error")
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		extractor        lockfile.Extractor
		purlType         string
		wantInventory    []*extractor.Inventory
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name:      "mock extractor",
			path:      "targetfile",
			extractor: MockExtractor{},
			purlType:  purl.TypeDebian,
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "reader content",
					Version:   "1.0",
					Metadata:  &osv.Metadata{PURLType: purl.TypeDebian},
					Locations: []string{"targetfile"},
				},
				&extractor.Inventory{
					Name:      "yolo content",
					Version:   "2.0",
					Metadata:  &osv.Metadata{PURLType: purl.TypeDebian},
					Locations: []string{"targetfile"},
				},
				&extractor.Inventory{
					Name:      "foobar content",
					Version:   "3.0",
					Metadata:  &osv.Metadata{PURLType: purl.TypeDebian},
					Locations: []string{"targetfile"},
				},
				&extractor.Inventory{
					Name:      "targetfile",
					Version:   "4.0",
					Metadata:  &osv.Metadata{PURLType: purl.TypeDebian},
					Locations: []string{"targetfile"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "mock extractor error",
			path:             "targetfile",
			extractor:        MockExtractor{err: errTestMock},
			purlType:         purl.TypeDebian,
			wantErr:          errTestMock,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collector := testcollector.New()

			w := osv.Wrapper{
				ExtractorName:    "testname",
				ExtractorVersion: 123,
				Extractor:        test.extractor,
				PURLType:         test.purlType,
				Stats:            collector,
			}

			r := strings.NewReader("reader content")
			fileSizeBytes := 100 * units.KiB

			tmp := t.TempDir()
			writeFile(t, filepath.Join(tmp, "yolo"), "yolo content")
			writeFile(t, filepath.Join(tmp, "foo", "bar"), "foobar content")

			input := &filesystem.ScanInput{
				FS:     scalibrfs.DirFS(tmp),
				Path:   test.path,
				Reader: r,
				Root:   tmp,
				Info: fakefs.FakeFileInfo{
					FileName: filepath.Base(test.path),
					FileMode: fs.ModePerm,
					FileSize: fileSizeBytes,
				},
			}

			got, err := w.Extract(context.Background(), input)
			if !cmp.Equal(err, test.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract() error: got %v, want %v", err, test.wantErr)
			}

			if diff := cmp.Diff(test.wantInventory, got); diff != "" {
				t.Errorf("Extract() (-want +got):\n%s", diff)
			}

			gotResultMetric := collector.FileExtractedResult(test.path)
			if test.wantResultMetric != "" && gotResultMetric != test.wantResultMetric {
				t.Errorf("Extract(%s) recorded result metric %v, want result metric %v", test.path, gotResultMetric, test.wantResultMetric)
			}

			gotFileSizeMetric := collector.FileExtractedFileSize(test.path)
			if gotFileSizeMetric != fileSizeBytes {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", test.path, gotFileSizeMetric, fileSizeBytes)
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	e := osv.Wrapper{}
	i := &extractor.Inventory{
		Name:    "namespace:name",
		Version: "1.2.3",
		Metadata: &osv.Metadata{
			PURLType: purl.TypeMaven,
		},
		Locations: []string{"location"},
	}
	want := &purl.PackageURL{
		Type:      purl.TypeMaven,
		Name:      "name",
		Namespace: "namespace",
		Version:   "1.2.3",
	}
	got, err := e.ToPURL(i)
	if err != nil {
		t.Fatalf("ToPURL(%v): %v", i, err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ToPURL(%v) (-want +got):\n%s", i, diff)
	}
}

func writeFile(t *testing.T, path string, content string) {
	err := os.MkdirAll(filepath.Dir(path), 0755)
	if err != nil {
		t.Fatalf("MkdirAll(): got %v, want nil", err)
	}

	err = os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		t.Fatalf("WriteFile(%s): got %v, want nil", path, err)
	}
}

type MockExtractor struct {
	err error
}

func (MockExtractor) ShouldExtract(path string) bool {
	return path == "match.json"
}
func (m MockExtractor) Extract(f lockfile.DepFile) ([]lockfile.PackageDetails, error) {
	if m.err != nil {
		return nil, m.err
	}
	r := []lockfile.PackageDetails{}

	// use reader
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	r = append(r, lockfile.PackageDetails{Name: string(b), Version: "1.0"})

	// use relative open
	g, err := f.Open("yolo")
	if err != nil {
		return nil, err
	}
	defer g.Close()
	b, err = io.ReadAll(g)
	if err != nil {
		return nil, err
	}
	r = append(r, lockfile.PackageDetails{Name: string(b), Version: "2.0"})

	// use absolute open
	g, err = f.Open(filepath.FromSlash("/foo/bar"))
	if err != nil {
		return nil, err
	}
	defer g.Close()
	b, err = io.ReadAll(g)
	if err != nil {
		return nil, err
	}
	r = append(r, lockfile.PackageDetails{Name: string(b), Version: "3.0"})

	// path
	r = append(r, lockfile.PackageDetails{Name: string(f.Path()), Version: "4.0"})

	return r, nil
}
