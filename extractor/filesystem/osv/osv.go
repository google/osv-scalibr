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

// Package osv provides a Wrapper for osv plugins.
package osv

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scanner/pkg/lockfile"
)

// Wrapper contains all the data to wrap a osv extractor to a scalibr extractor.
type Wrapper struct {
	ExtractorName    string
	ExtractorVersion int
	PURLType         string
	Extractor        lockfile.Extractor

	// Optional. A stats.Collector for reporting internal metrics.
	Stats stats.Collector

	// Optional. A config value for the maximum file size this extractor will
	// treat as required in `FileRequired`.
	MaxFileSizeBytes int64
}

// Name of the extractor.
func (e Wrapper) Name() string { return e.ExtractorName }

// Version of the extractor.
func (e Wrapper) Version() int { return e.ExtractorVersion }

// Requirements of the extractor.
func (e Wrapper) Requirements() *plugin.Capabilities { return &plugin.Capabilities{DirectFS: true} }

// FileRequired returns true if the specified file matches the extractor pattern.
func (e Wrapper) FileRequired(path string, stat func() (fs.FileInfo, error)) bool {
	if !e.Extractor.ShouldExtract(path) {
		return false
	}

	fileinfo, err := stat()
	if err != nil {
		return false
	}
	if e.MaxFileSizeBytes > 0 && fileinfo.Size() > e.MaxFileSizeBytes {
		e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Wrapper) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract wraps the osv Extract method.
func (e Wrapper) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	full := filepath.Join(input.Root, input.Path)
	osvpkgs, err := e.Extractor.Extract(WrapInput(input))
	if err != nil {
		e.reportFileExtracted(input.Path, input.Info, filesystem.ExtractorErrorToFileExtractedResult(err))
		return nil, fmt.Errorf("osvExtractor.Extract(%s): %w", full, err)
	}

	r := []*extractor.Inventory{}
	for _, p := range osvpkgs {
		r = append(r, &extractor.Inventory{
			Name:    p.Name,
			Version: p.Version,
			Metadata: &Metadata{
				PURLType:  e.PURLType,
				Commit:    p.Commit,
				Ecosystem: string(p.Ecosystem),
				CompareAs: string(p.CompareAs),
			},
			Locations: []string{input.Path},
		})
	}

	e.reportFileExtracted(input.Path, input.Info, stats.FileExtractedResultSuccess)
	return r, nil
}

func (e Wrapper) reportFileExtracted(path string, fileinfo fs.FileInfo, result stats.FileExtractedResult) {
	if e.Stats == nil {
		return
	}
	var fileSizeBytes int64
	if fileinfo != nil {
		fileSizeBytes = fileinfo.Size()
	}
	e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// WrapInput returns an implementation of OSVs DepFile using a scalibr ScanInput.
func WrapInput(input *filesystem.ScanInput) lockfile.DepFile {
	return fileWrapper{input: input}
}

type fileWrapper struct {
	input *filesystem.ScanInput
}

// Implement io.Reader interface
func (fw fileWrapper) Read(p []byte) (n int, err error) {
	return fw.input.Reader.Read(p)
}
func (fw fileWrapper) Open(path string) (lockfile.NestedDepFile, error) {
	cwd := fw.input.Root
	if !filepath.IsAbs(path) {
		cwd = filepath.Join(fw.input.Root, filepath.Dir(fw.input.Path))
	}
	return lockfile.OpenLocalDepFile(filepath.Join(cwd, path))
}

func (fw fileWrapper) Path() string {
	return fw.input.Path
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Wrapper) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	m := i.Metadata.(*Metadata)
	name := i.Name
	namespace := ""
	if m.PURLType == purl.TypeMaven && strings.Contains(name, ":") {
		t := strings.Split(name, ":")
		namespace = t[0] // group id
		name = t[1]      // artifact id
	}
	return &purl.PackageURL{
		Type:      m.PURLType,
		Namespace: namespace,
		Name:      name,
		Version:   i.Version,
	}
}

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
func (e Wrapper) Ecosystem(i *extractor.Inventory) string {
	return i.Metadata.(*Metadata).Ecosystem
}
