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
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	archivemeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"go.uber.org/multierr"
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
	// MaxFileSizeBytes is the maximum size of a file that can be extracted.
	// If this limit is greater than zero and a file is encountered that is larger
	// than this limit, the file is ignored by returning false for `FileRequired`.
	MaxFileSizeBytes int64
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
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
}

// Extractor extracts Java packages from archive files.
type Extractor struct {
	maxZipDepth         int
	maxFileSizeBytes    int64
	maxOpenedBytes      int64
	minZipBytes         int
	extractFromFilename bool
	hashJars            bool
	stats               stats.Collector
}

// DefaultConfig returns the default configuration for the Java archive extractor.
func DefaultConfig() Config {
	return Config{
		MaxZipDepth:         defaultMaxZipDepth,
		MaxFileSizeBytes:    0,
		MaxOpenedBytes:      defaultMaxZipBytes,
		MinZipBytes:         defaultMinZipBytes,
		ExtractFromFilename: true,
		HashJars:            true,
		Stats:               nil,
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
		maxFileSizeBytes:    cfg.MaxFileSizeBytes,
		maxOpenedBytes:      cfg.MaxOpenedBytes,
		minZipBytes:         cfg.MinZipBytes,
		extractFromFilename: cfg.ExtractFromFilename,
		hashJars:            cfg.HashJars,
		stats:               cfg.Stats,
	}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches java archive file patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if !IsArchive(filepath.ToSlash(path)) {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.stats == nil {
		return
	}
	e.stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts java packages from archive files passed through input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, openedBytes, err := e.extractWithMax(ctx, input, 1, 0)
	if e.stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:              input.Path,
			Result:            filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes:     fileSizeBytes,
			UncompressedBytes: openedBytes,
		})
	}
	return inventory.Inventory{Packages: pkgs}, err
}

// extractWithMax recursively unzips and extracts packages from archive files starting at input.
//
// It returns early with an error if max depth or max opened bytes is reached.
// Extracted packages are returned even if an error has occurred.
func (e Extractor) extractWithMax(ctx context.Context, input *filesystem.ScanInput, depth int, openedBytes int64) ([]*extractor.Package, int64, error) {
	// Return early if any max/min thresholds are hit.
	if depth > e.maxZipDepth {
		return nil, openedBytes, fmt.Errorf("%s reached max zip depth %d", e.Name(), depth)
	}
	if oBytes := openedBytes + input.Info.Size(); oBytes > e.maxOpenedBytes {
		return nil, oBytes, fmt.Errorf(
			"%w: %s reached max opened bytes of %d at %q",
			filesystem.ErrExtractorMemoryLimitExceeded, e.Name(), oBytes, input.Path)
	}
	if int(input.Info.Size()) < e.minZipBytes {
		log.Warnf("%s ignoring zip with size %d because it is smaller than min size %d at %q",
			e.Name(), input.Info.Size(), e.minZipBytes, input.Path)
		return nil, openedBytes, nil
	}

	// Create ReaderAt
	r, ok := input.Reader.(io.ReaderAt)
	l := input.Info.Size()
	if !ok {
		log.Debugf("Reader of %s does not implement ReaderAt. Fall back to read to memory.", input.Path)
		b, err := io.ReadAll(input.Reader)
		if err != nil {
			return nil, openedBytes, fmt.Errorf("%s failed to read file: %w", e.Name(), err)
		}
		openedBytes += int64(len(b))
		// Check size again in case input.Info.Size() was not accurate. Return early if hit max.
		if openedBytes > e.maxOpenedBytes {
			return nil, openedBytes, fmt.Errorf(
				"%w: %s reached max opened bytes of %d at %q",
				filesystem.ErrExtractorMemoryLimitExceeded, e.Name(), openedBytes, input.Path)
		}
		r = bytes.NewReader(b)
		l = int64(len(b))
	}

	// Hash Jar
	sha1 := ""
	if e.hashJars {
		h, err := hashJar(r.(io.Reader))
		if err != nil {
			log.Errorf("HashJar(%q) err: %v", input.Path, err)
			// continue extracting even if hashing failed
		}
		if _, err := r.(io.Seeker).Seek(0, 0); err != nil {
			log.Errorf("%q: Failed to seek to the start, after hashing: %v", input.Path, err)
		}
		sha1 = h
	}

	// Unzip Jar
	zipReader, err := zip.NewReader(r, l)
	if err != nil {
		return nil, openedBytes, fmt.Errorf("%s invalid archive: %w", e.Name(), err)
	}

	log.Debugf("extract jar archive: %s", input.Path)

	// Aggregate errors while looping through files in the zip to continue extraction of other files.
	errs := []error{}
	pkgs := []*extractor.Package{}
	packagePom := []*extractor.Package{}
	packageManifest := []*extractor.Package{}

	for _, file := range zipReader.File {
		// Return if canceled or exceeding deadline.
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			// Ignore local findings from pom and manifest, as they are incomplete.
			return pkgs, openedBytes, fmt.Errorf("%s halted due to context deadline exceeded", e.Name())
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			// Ignore local findings from pom and manifest, as they are incomplete.
			return pkgs, openedBytes, fmt.Errorf("%s halted due to context was canceled", e.Name())
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
				packagePom = append(packagePom, &extractor.Package{
					Name:     fmt.Sprintf("%s:%s", pp.GroupID, pp.ArtifactID),
					Version:  pp.Version,
					PURLType: purl.TypeMaven,
					Metadata: &archivemeta.Metadata{
						ArtifactID: pp.ArtifactID,
						GroupID:    pp.GroupID,
						SHA1:       sha1,
					},
					Locations: []string{input.Path, path},
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
				packageManifest = append(packageManifest, &extractor.Package{
					Name:     fmt.Sprintf("%s:%s", mf.GroupID, mf.ArtifactID),
					Version:  mf.Version,
					PURLType: purl.TypeMaven,
					Metadata: &archivemeta.Metadata{
						ArtifactID: mf.ArtifactID,
						GroupID:    mf.GroupID,
						SHA1:       sha1,
					},
					Locations: []string{input.Path, path},
				})
			}

		case IsArchive(file.Name):
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
				subInput := &filesystem.ScanInput{Path: path, Info: file.FileInfo(), Reader: f}
				var subPackage []*extractor.Package
				subPackage, openedBytes, err = e.extractWithMax(ctx, subInput, depth+1, openedBytes)
				// Prepend the current input path
				for i := range subPackage {
					subPackage[i].Locations = append([]string{input.Path}, subPackage[i].Locations...)
				}
				if err != nil {
					log.Errorf("%s failed to extract %q: %v", e.Name(), path, err)
					errs = append(errs, err)
					return
				}
				pkgs = append(pkgs, subPackage...)
			}()
		}
	}

	pkgs = append(pkgs, packagePom...)

	// If there is no pom.properties, try combining MANIFEST.MF and filename.
	packageFilename := []*extractor.Package{}
	if len(packagePom) == 0 && e.extractFromFilename {
		p := ParseFilename(input.Path)
		if p != nil {
			log.Debugf("PropsFromFilename(%q): %+v", input.Path, p)
			// All Maven packages require a group ID as part of the package name, but
			// they are usually not part of the filename of the JAR. However, for some
			// legacy packages that were created before the reverse-domain convention
			// was established, the group ID is the same as the artifact ID (e.g.
			// junit:junit or commons-httpclient:commons-httpclient). Unless we find
			// the group ID from another source, we default to assuming that the group
			// ID is the artifact ID since that is how vulnerabilities are reported
			// for these legacy packages (e.g.
			// https://github.com/advisories/GHSA-3832-9276-x7gf).
			groupID := p.ArtifactID
			if p.GroupID != "" {
				groupID = strings.ToLower(p.GroupID)
			}
			// If manifest.mf was found, use GroupID from manifest instead, if
			// present. Then remove manifest from the Package.
			if len(packageManifest) == 1 {
				metadata := packageManifest[0].Metadata.(*archivemeta.Metadata)
				if metadata.GroupID != "" {
					groupID = metadata.GroupID
					packageManifest = nil
				}
			}
			packageFilename = append(packageFilename, &extractor.Package{
				Name:     fmt.Sprintf("%s:%s", groupID, p.ArtifactID),
				Version:  p.Version,
				PURLType: purl.TypeMaven,
				Metadata: &archivemeta.Metadata{
					ArtifactID: p.ArtifactID,
					GroupID:    groupID,
					SHA1:       sha1,
				},
				Locations: []string{input.Path},
			})
		}
	}
	pkgs = append(pkgs, packageFilename...)

	if len(packagePom) == 0 && len(packageFilename) == 0 {
		pkgs = append(pkgs, packageManifest...)
	}

	// If nothing worked, return the hash.
	if len(pkgs) == 0 && sha1 != "" {
		pkgs = append(pkgs, &extractor.Package{
			Name:     "unknown",
			Version:  "unknown",
			PURLType: purl.TypeMaven,
			Metadata: &archivemeta.Metadata{
				ArtifactID: "unknown",
				GroupID:    "unknown",
				SHA1:       sha1,
			},
			Locations: []string{input.Path},
		})
	}

	// Aggregate errors.
	err = multierr.Combine(errs...)
	if err != nil {
		return pkgs, openedBytes, fmt.Errorf("error(s) in extractor %s: %w", e.Name(), err)
	}

	return pkgs, openedBytes, err
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

// IsArchive returns true if the file path ends with one of the supported archive extensions.
func IsArchive(path string) bool {
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
