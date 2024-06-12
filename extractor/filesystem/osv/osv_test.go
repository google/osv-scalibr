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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/purl"
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
	w := osv.Wrapper{
		ExtractorName:    "testname",
		ExtractorVersion: 123,
		Extractor:        MockExtractor{},
		PURLType:         purl.TypeDebian,
	}

	tests := []struct {
		path string
		want bool
	}{
		{path: "match.json", want: true},
		{path: "foo", want: false},
		{path: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			isRequired := w.FileRequired(tt.path, nil)
			if isRequired != tt.want {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	w := osv.Wrapper{
		ExtractorName:    "testname",
		ExtractorVersion: 123,
		Extractor:        MockExtractor{},
		PURLType:         purl.TypeDebian,
	}
	want := []*extractor.Inventory{
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
	}

	r := strings.NewReader("reader content")

	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "yolo"), "yolo content")
	writeFile(t, filepath.Join(tmp, "foo", "bar"), "foobar content")

	input := &filesystem.ScanInput{Path: "targetfile", Reader: r, ScanRoot: tmp}

	got, err := w.Extract(context.Background(), input)
	if err != nil {
		t.Fatalf("Extract(): got %v, want nil", err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Extract() (-want +got):\n%s", diff)
	}
}

func TestExtractErr(t *testing.T) {
	wantErr := fmt.Errorf("test error")
	w := osv.Wrapper{
		ExtractorName:    "testname",
		ExtractorVersion: 123,
		Extractor:        MockExtractor{err: wantErr},
		PURLType:         purl.TypeDebian,
	}

	r := strings.NewReader("reader content")
	tmp := t.TempDir()
	input := &filesystem.ScanInput{Path: "targetfile", Reader: r, ScanRoot: tmp}

	_, err := w.Extract(context.Background(), input)
	if !cmp.Equal(err, wantErr, cmpopts.EquateErrors()) {
		t.Fatalf("Extract() error: got %v, want %v", err, wantErr)
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
