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

// Package wheelegg extracts wheel and egg files.
package wheelegg

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/textproto"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/internal/units"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/wheelegg"

	// defaultMaxFileSize is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSize = 100 * units.MiB
)

// Extractor extracts python packages from wheel/egg files.
type Extractor struct {
	maxFileSize int64
}

// Config is the configuration for the Extractor.
type Config struct {
	// MaxFileSize is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	MaxFileSize int64
}

// DefaultConfig returns the default configuration for the wheel/egg extractor.
func DefaultConfig() Config {
	return Config{
		MaxFileSize: defaultMaxFileSize,
	}
}

// New returns a wheel/egg extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		maxFileSize: cfg.MaxFileSize,
	}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

var (
	requiredFiles = []string{
		// Metadata format
		"EGG-INFO/PKG-INFO",
		".egg-info",
		".egg-info/PKG-INFO",
		".dist-info/METADATA",
		// zip file with Metadata files inside.
		".egg",
	}
)

// FileRequired returns true if the specified file matches python Metadata file
// patterns.
func (e Extractor) FileRequired(path string, _ fs.FileMode) bool {
	// For Windows
	path = filepath.ToSlash(path)

	for _, r := range requiredFiles {
		if strings.HasSuffix(path, r) {
			return true
		}
	}
	return false
}

// Extract extracts packages from wheel/egg files passed through the scan input.
// For .egg files, input.Info.Size() is required to unzip the file.
func (e Extractor) Extract(ctx context.Context, input *extractor.ScanInput) ([]*extractor.Inventory, error) {
	if input.Info != nil && input.Info.Size() > e.maxFileSize {
		return nil, fmt.Errorf("package.json file %s is too large: %d", input.Path, input.Info.Size())
	}
	if strings.HasSuffix(input.Path, ".egg") {
		// TODO(b/280417821): In case extractZip returns no inventory, we could parse the filename.
		return e.extractZip(ctx, input)
	}

	i, err := e.extractSingleFile(input.Reader, input.Path)
	if err != nil {
		return nil, err
	}
	return []*extractor.Inventory{i}, nil
}

// ErrSizeNotSet will trigger when Info.Size() is not set.
var ErrSizeNotSet = errors.New("input.Info is nil, but should have Size set")

func (e Extractor) extractZip(ctx context.Context, input *extractor.ScanInput) ([]*extractor.Inventory, error) {
	r, err := newReaderAt(input.Reader)
	if err != nil {
		return nil, fmt.Errorf("newReaderAt(%s): %w", input.Path, err)
	}

	if input.Info == nil {
		return nil, ErrSizeNotSet
	}
	s := input.Info.Size()
	zr, err := zip.NewReader(r, s)
	if err != nil {
		return nil, fmt.Errorf("zip.NewReader(%s): %w", input.Path, err)
	}
	inventory := []*extractor.Inventory{}
	for _, f := range zr.File {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !e.FileRequired(f.Name, f.Mode()) {
			continue
		}
		i, err := e.openAndExtract(f, input)
		if err != nil {
			return inventory, err
		}
		inventory = append(inventory, i)
	}
	return inventory, nil
}

func newReaderAt(ioReader io.Reader) (io.ReaderAt, error) {
	r, ok := ioReader.(io.ReaderAt)
	if ok {
		return r, nil
	}

	// Fallback: In case ioReader does not implement ReadAt, we use a reader on byte buffer instead, which
	// supports ReadAt.
	buff := bytes.NewBuffer([]byte{})
	_, err := io.Copy(buff, ioReader)
	if err != nil {
		return nil, fmt.Errorf("io.Copy(): %w", err)
	}

	return bytes.NewReader(buff.Bytes()), nil
}

func (e Extractor) openAndExtract(f *zip.File, input *extractor.ScanInput) (*extractor.Inventory, error) {
	r, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("On %q: Open(%s): %w", input.Path, f.Name, err)
	}
	defer r.Close()

	// TODO(b/280438976): Store the path inside the zip file.
	i, err := e.extractSingleFile(r, input.Path)
	if err != nil {
		return nil, err
	}

	return i, nil
}

func (e Extractor) extractSingleFile(r io.Reader, path string) (*extractor.Inventory, error) {
	i, err := parse(r)
	if err != nil {
		return nil, fmt.Errorf("wheelegg.parse(%s): %w", path, err)
	}

	i.Locations = []string{path}
	i.Extractor = e.Name()
	return i, nil
}

func parse(r io.Reader) (*extractor.Inventory, error) {
	rd := textproto.NewReader(bufio.NewReader(r))
	h, err := rd.ReadMIMEHeader()
	name := h.Get("Name")
	version := h.Get("version")
	if name == "" || version == "" {
		// In case we got name and version but also an error, we ignore the error. This can happen in
		// malformed files like passlib 1.7.4.
		if err != nil {
			return nil, fmt.Errorf("ReadMIMEHeader(): %w %s %s", err, h.Get("Name"), h.Get("version"))
		}
		return nil, fmt.Errorf("Name or version is empty (name: %q, version: %q)", name, version)
	}

	return &extractor.Inventory{
		Name:    name,
		Version: version,
		Metadata: &PythonPackageMetadata{
			Author:      h.Get("Author"),
			AuthorEmail: h.Get("Author-email"),
		},
	}, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return &purl.PackageURL{
		Type:    purl.TypePyPi,
		Name:    strings.ToLower(i.Name),
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }
