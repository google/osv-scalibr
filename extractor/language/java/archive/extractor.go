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

// Package archive extracts Java archive files.
package archive

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"go.uber.org/multierr"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/internal/units"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "java/archive"

	// defaultMaxZipDepth is the maximum number of inner zip files within an archive the default extractor will unzip.
	// Once reached, no more inner zip files will be explored during extraction.
	defaultMaxZipDepth = 16
	// defaultMaxZipBytes in the maximum number of bytes recursively read from an archive file.
	// If this limit is reached, the default extractor is halted and results so far are returned.
	defaultMaxZipBytes = 4 * units.GiB
	// defaultMinZipBytes is slightly larger than an empty zip file which is 22 bytes.
	// https://en.wikipedia.org/wiki/ZIP_(file_format)#:~:text=Viewed%20as%20an%20ASCII%20string,file%20are%20usually%20%22PK%22.
	defaultMinZipBytes = 30
)

var (
	archiveExtensions = []string{".jar", ".war", ".ear", ".jmod", ".par", ".sar", ".jpi", ".hpi", ".lpkg", ".nar"}
)

// Config is the configuration for the Extractor.
type Config struct {
	// MaxZipDepth is the maximum number of inner zip files within an archive the extractor will unzip.
	// Once reached, no more inner zip files will be explored during extraction.
	MaxZipDepth int
	// MaxOpenedBytes is the maximum number of bytes recursively read from an archive file.
	// If this limit is reached, extraction is halted and results so far are returned.
	MaxOpenedBytes int64
	// MinZipBytes is use to ignore empty zip files during extraction.
	// Zip files smaller than minZipBytes are ignored.
	MinZipBytes int
	// ExtractFromFilename configures if JAR files should be extracted from filenames when no "pom.properties" is present.
	ExtractFromFilename bool
	// HashJars configures if JAR files should be hashed with base64(sha1()), which can be used in deps.dev.
	HashJars bool
}

// Extractor extracts Java packages from archive files.
type Extractor struct {
	maxZipDepth         int
	maxOpenedBytes      int64
	minZipBytes         int
	extractFromFilename bool
	hashJars            bool
}

// DefaultConfig returns the default configuration for the Java archive extractor.
func DefaultConfig() Config {
	return Config{
		MaxZipDepth:         defaultMaxZipDepth,
		MaxOpenedBytes:      defaultMaxZipBytes,
		MinZipBytes:         defaultMinZipBytes,
		ExtractFromFilename: true,
		HashJars:            true,
	}
}

// New returns a Java archive extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		maxZipDepth:         cfg.MaxZipDepth,
		maxOpenedBytes:      cfg.MaxOpenedBytes,
		minZipBytes:         cfg.MinZipBytes,
		extractFromFilename: cfg.ExtractFromFilename,
		hashJars:            cfg.HashJars,
	}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// FileRequired returns true if the specified file matches java archive file patterns.
func (e Extractor) FileRequired(path string, _ fs.FileMode) bool {
	// For Windows
	path = filepath.ToSlash(path)
	return isArchive(path)
}

// Extract extracts java packages from archive files passed through input.
func (e Extractor) Extract(ctx context.Context, input *extractor.ScanInput) ([]*extractor.Inventory, error) {
	return e.extractWithMax(ctx, input, 1, 0)
}

// extractWithMax recursively unzips and extracts packages from archive files starting at input.
//
// It returns early with an error if max depth or max opened bytes is reached.
// Extracted packages are returned even if an error has occurred.
func (e Extractor) extractWithMax(ctx context.Context, input *extractor.ScanInput, depth int, openedBytes int64) ([]*extractor.Inventory, error) {
	// Return early if any max/min thresholds are hit.
	if depth > e.maxZipDepth {
		return nil, fmt.Errorf("%s reached max zip depth %d at %q", e.Name(), depth, input.Path)
	}
	if oBytes := openedBytes + input.Info.Size(); oBytes > e.maxOpenedBytes {
		return nil, fmt.Errorf("%s reached max opened bytes of %d at %q", e.Name(), oBytes, input.Path)
	}
	if int(input.Info.Size()) < e.minZipBytes {
		log.Warnf("%s ignoring zip with size %d because it is smaller than min size %d at %q",
			e.Name(), input.Info.Size(), e.minZipBytes, input.Path)
		return nil, nil
	}

	// Create ReaderAt
	r, ok := input.Reader.(io.ReaderAt)
	l := input.Info.Size()
	if !ok {
		log.Debugf("Reader of %s does not implement ReaderAt. Fall back to read to memory.", input.Path)
		b, err := io.ReadAll(input.Reader)
		if err != nil {
			return nil, fmt.Errorf("%s failed to read file at %q: %w", e.Name(), input.Path, err)
		}
		openedBytes += int64(len(b))
		// Check size again in case input.Info.Size() was not accurate. Return early if hit max.
		if openedBytes > e.maxOpenedBytes {
			return nil, fmt.Errorf("%s reached max opened bytes of %d at %q", e.Name(), openedBytes, input.Path)
		}
		r = bytes.NewReader(b)
		l = int64(len(b))
	}

	// Hash Jar
	sha1 := ""
	if e.hashJars {
		h, err := hashJar(r.(io.Reader))
		if err != nil {
			log.Errorf("HashJar(%q) err: %v", filepath.Join(input.ScanRoot, input.Path), err)
			// continue extracting even if hashing failed
		}
		if _, err := r.(io.Seeker).Seek(0, 0); err != nil {
			log.Errorf("%q: Failed to seek to the start, after hashing: %v", filepath.Join(input.ScanRoot, input.Path), err)
		}
		sha1 = h
	}

	// Unzip Jar
	zipReader, err := zip.NewReader(r, l)
	if err != nil {
		return nil, fmt.Errorf("%s invalid archive at %q: %w", e.Name(), input.Path, err)
	}

	log.Debugf("extract jar archive: %s", input.Path)

	// Aggregate errors while looping through files in the zip to continue extraction of other files.
	errs := []error{}
	inventory := []*extractor.Inventory{}
	inventoryPom := []*extractor.Inventory{}
	inventoryManifest := []*extractor.Inventory{}

	for _, file := range zipReader.File {
		// Return if canceled or exceeding deadline.
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			// Ignore local findings from pom and manifest, as they are incomplete.
			return inventory, fmt.Errorf("%s halted at %q because context deadline exceeded", e.Name(), input.Path)
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			// Ignore local findings from pom and manifest, as they are incomplete.
			return inventory, fmt.Errorf("%s halted at %q because context was canceled", e.Name(), input.Path)
		}

		path := filepath.Join(input.Path, file.Name)
		switch {
		case filepath.Base(file.Name) == "pom.properties":
			pp, err := parsePomProps(file)
			if err != nil {
				log.Errorf("%s failed to extract from pom.properties at %q: %v", e.Name(), path, err)
				errs = append(errs, err)
				continue
			}
			if pp.valid() {
				inventoryPom = append(inventoryPom, &extractor.Inventory{
					Name:    pp.ArtifactID,
					Version: pp.Version,
					Metadata: &Metadata{
						ArtifactID: pp.ArtifactID,
						GroupID:    pp.GroupID,
						SHA1:       sha1,
					},
					Locations: []string{path},
					Extractor: e.Name(),
				})
			}

		case isManifest(file.Name):
			mf, err := parseManifest(file)
			if err != nil {
				log.Errorf("%s failed to extract from manifest.mf at %q: %v", e.Name(), path, err)
				errs = append(errs, err)
				continue
			}
			if mf.valid() {
				inventoryManifest = append(inventoryManifest, &extractor.Inventory{
					Name:    mf.ArtifactID,
					Version: mf.Version,
					Metadata: &Metadata{
						ArtifactID: mf.ArtifactID,
						GroupID:    mf.GroupID,
						SHA1:       sha1,
					},
					Locations: []string{path},
					Extractor: e.Name(),
				})
			}

		case isArchive(file.Name):
			// Anonymous func needed to defer f.Close().
			func() {
				f, err := file.Open()
				if err != nil {
					log.Errorf("%s failed to open file  %q: %v", e.Name(), path, err)
					errs = append(errs, err)
					return
				}
				// Do not need to handle error from f.Close() because it only happens if the file was previously closed.
				defer f.Close()
				subInput := &extractor.ScanInput{Path: path, Info: file.FileInfo(), Reader: f}
				subInventory, err := e.extractWithMax(ctx, subInput, depth+1, openedBytes)
				if err != nil {
					log.Errorf("%s failed to extract %q: %v", e.Name(), path, err)
					errs = append(errs, err)
					return
				}
				inventory = append(inventory, subInventory...)
			}()
		}
	}

	inventory = append(inventory, inventoryPom...)

	// If there is no pom.properties, try combining MANIFEST.MF and filename.
	inventoryFilename := []*extractor.Inventory{}
	if len(inventoryPom) == 0 && e.extractFromFilename {
		p := ParseFilename(input.Path)
		if p != nil {
			log.Debugf("PropsFromFilename(%q): %+v", input.Path, p)
			groupID := p.ArtifactID
			if p.GroupID != "" {
				groupID = strings.ToLower(p.GroupID)
			}
			// If manifest.mf was found, use GroupID from manifest instead. Then remove manifest from the
			// Inventory.
			if len(inventoryManifest) == 1 {
				groupID = inventoryManifest[0].Metadata.(*Metadata).GroupID
			}
			inventoryFilename = append(inventoryFilename, &extractor.Inventory{
				Name:    p.ArtifactID,
				Version: p.Version,
				Metadata: &Metadata{
					ArtifactID: p.ArtifactID,
					GroupID:    groupID,
					SHA1:       sha1,
				},
				Locations: []string{input.Path},
				Extractor: e.Name(),
			})
		}
	}
	inventory = append(inventory, inventoryFilename...)

	if len(inventoryPom) == 0 && len(inventoryFilename) == 0 {
		inventory = append(inventory, inventoryManifest...)
	}

	// If nothing worked, return the hash.
	if len(inventory) == 0 && sha1 != "" {
		inventory = append(inventory, &extractor.Inventory{
			Name:    "unknown",
			Version: "unknown",
			Metadata: &Metadata{
				ArtifactID: "unknown",
				GroupID:    "unknown",
				SHA1:       sha1,
			},
			Locations: []string{input.Path},
			Extractor: e.Name(),
		})
	}

	// Aggregate errors.
	err = multierr.Combine(errs...)
	if err != nil {
		return inventory, fmt.Errorf("error(s) in extractor %s:%s", e.Name(), err)
	}

	return inventory, err
}

// hashJar returns base64(sha1()) of the file. This is compatible to dev.deps.
func hashJar(r io.Reader) (string, error) {
	// SHA1
	hasher := sha1.New()
	_, err := io.Copy(hasher, r)
	if err != nil {
		return "", err
	}
	h := hasher.Sum(nil)

	// Base64
	return base64.StdEncoding.EncodeToString(h), nil
}

func isArchive(path string) bool {
	ext := filepath.Ext(path)
	for _, archiveExt := range archiveExtensions {
		if strings.EqualFold(ext, archiveExt) {
			return true
		}
	}
	return false
}

func isManifest(path string) bool {
	return strings.ToLower(filepath.Base(path)) == "manifest.mf"
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	m := i.Metadata.(*Metadata)
	return &purl.PackageURL{
		Type:      purl.TypeMaven,
		Namespace: strings.ToLower(m.GroupID),
		Name:      strings.ToLower(m.ArtifactID),
		Version:   i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }
