// Copyright 2026 Google LLC
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

// Package deb extracts packages from a deb file.
package deb

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/common"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/ulikunitz/xz"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/deb"
	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 100 * units.MiB
)

// Extractor extracts packages from deb files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a deb extractor.
//
// For most use cases, initialize with:
// ```
// e := New(&cpb.PluginConfig{})
// ```
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.DebConfig { return c.GetDeb() })
	if specific.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = specific.GetMaxFileSizeBytes()
	}

	e := &Extractor{
		maxFileSizeBytes: maxFileSizeBytes,
	}
	return e, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is a deb file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := filepath.ToSlash(api.Path())
	if !strings.HasSuffix(path, ".deb") {
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
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts a package from a deb file passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkg, err := e.extractFromInput(input)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("%s failed: %w", Name, err)
	}
	if e.Stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inventory.Inventory{Packages: []*extractor.Package{pkg}}, err
}

func (e Extractor) extractFromInput(input *filesystem.ScanInput) (*extractor.Package, error) {
	// Extract the deb to a temporary directory
	tempDir, err := common.ARToTempDir(input.Reader, e.maxFileSizeBytes)
	if err != nil {
		return nil, err
	}
	// Ensure the base temp dir is cleaned up when extraction finishes
	defer os.RemoveAll(tempDir)

	// Define the possible control file names we are looking for
	targets := []string{"control.tar.xz", "control.tar.gz", "control.tar"}
	var targetFile string
	var found bool

	// Check which control archive exists in the temp directory
	for _, name := range targets {
		path := filepath.Join(tempDir, name)
		if _, err := os.Stat(path); err == nil {
			targetFile = path
			found = true
			break
		}
	}

	if !found {
		return nil, errors.New("not a valid deb file")
	}

	// Open the discovered control archive
	file, err := os.Open(targetFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open control archive: %w", err)
	}
	defer file.Close()

	// Set up the reader pipeline based on the file type
	var tarReader io.Reader
	ext := filepath.Ext(targetFile)

	switch ext {
	case ".gz":
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		tarReader = gzReader

	case ".xz":
		xzReader, err := xz.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("failed to create xz reader: %w", err)
		}
		tarReader = xzReader

	case ".tar":
		tarReader = file

	default:
		return nil, fmt.Errorf("unexpected file extension: %s", ext)
	}
	// Extract the control tar file contents to a new temporary directory
	controlTempDir, err := common.TARToTempDir(tarReader)
	if err != nil {
		return nil, fmt.Errorf("failed to extract control tar: %w", err)
	}
	defer os.RemoveAll(controlTempDir)
	// Parse the control file and return the package discovered
	pkg, err := getPackageFromControlFile(controlTempDir, input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse control file: %w", err)
	}

	return pkg, nil
}

func getPackageFromControlFile(tempDir string, input *filesystem.ScanInput) (*extractor.Package, error) {
	// Open the control file
	file, err := os.Open(filepath.Join(tempDir, "control"))
	if err != nil {
		return nil, fmt.Errorf("failed to open control file: %w", err)
	}
	defer file.Close()
	rd := textproto.NewReader(bufio.NewReader(file))
	var pkg *extractor.Package
	h, err := rd.ReadMIMEHeader()
	if err != nil {
		if !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("failed to read MIME header from control file: %w", err)
		}
	}

	// Skip empty file
	if len(h) == 0 {
		return nil, errors.New("empty Control file")
	}

	pkgName := h.Get("Package")
	pkgVersion := h.Get("Version")
	if pkgName == "" {
		return nil, errors.New("package name is empty in the control file")
	}
	if pkgVersion == "" {
		return nil, errors.New("package version is empty in the control file")
	}
	description := strings.ToLower(h.Get("Description"))
	var vexes []*vex.PackageExploitabilitySignal
	if strings.Contains(description, "transitional package") ||
		strings.Contains(description, "transitional dummy package") ||
		strings.Contains(description, "transitional empty package") {
		vexes = append(vexes, &vex.PackageExploitabilitySignal{
			Plugin:          Name,
			Justification:   vex.ComponentNotPresent,
			MatchesAllVulns: true,
		})
	}
	pkg = &extractor.Package{
		Name:     pkgName,
		Version:  pkgVersion,
		PURLType: purl.TypeDebian,
		Metadata: &dpkgmeta.Metadata{
			PackageName:    pkgName,
			PackageVersion: pkgVersion,
			Maintainer:     h.Get("Maintainer"),
			Architecture:   h.Get("Architecture"),
		},
		Location:              extractor.LocationFromPath(input.Path),
		ExploitabilitySignals: vexes,
	}
	sourceName, sourceVersion, err := parseSourceNameVersion(h.Get("Source"))
	if err != nil {
		return nil, fmt.Errorf("parseSourceNameVersion(%q): %w", h.Get("Source"), err)
	}
	if sourceName != "" {
		pkg.Metadata.(*dpkgmeta.Metadata).SourceName = sourceName
		pkg.Metadata.(*dpkgmeta.Metadata).SourceVersion = sourceVersion
	}
	return pkg, nil
}

func parseSourceNameVersion(source string) (string, string, error) {
	if source == "" {
		return "", "", nil
	}
	// Format is either "name" or "name (version)"
	if idx := strings.Index(source, " ("); idx != -1 {
		if !strings.HasSuffix(source, ")") {
			return "", "", fmt.Errorf("invalid deb Source field: %q", source)
		}
		n := source[:idx]
		v := source[idx+2 : len(source)-1]
		return n, v, nil
	}
	return source, "", nil
}
