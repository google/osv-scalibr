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

// Package gobinary extracts packages from buildinfo inside go binaries files.
package gobinary

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"errors"
	"io"
	"io/fs"
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "go/binary"
	// devel is the version of the development binary.
	devel = "(devel)"
)

var (
	// reVersion is a regexp to parse the Go version from the binary content.
	reVersion = regexp.MustCompile(`(\x00|\x{FFFD})(.L)?(?P<version>v?(\d+\.\d+\.\d+[-\w]*[+\w]*))\x00`)
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum size of a file that can be extracted.
	// If this limit is greater than zero and a file is encountered that is larger
	// than this limit, the file is ignored by returning false for `FileRequired`.
	MaxFileSizeBytes int64
	// VersionFromContent enables extracting the module version from the binary content.
	// This is off by default because the operation is expensive as it uses a regexp to parse the
	// binary content.
	VersionFromContent bool
}

// Extractor extracts packages from buildinfo inside go binaries files.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64

	// VersionFromBinary enables extracting the module version from the binary content.
	// This operation is expensive because it uses a regexp to parse the binary content.
	VersionFromContent bool
}

// DefaultConfig returns a default configuration for the extractor.
func DefaultConfig() Config {
	return Config{
		Stats:              nil,
		MaxFileSizeBytes:   0,
		VersionFromContent: false,
	}
}

// New returns a Go binary extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:              cfg.Stats,
		maxFileSizeBytes:   cfg.MaxFileSizeBytes,
		VersionFromContent: cfg.VersionFromContent,
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

// FileRequired returns true if the specified file is marked executable.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	if !filesystem.IsInterestingExecutable(api) {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}

	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(api.Path(), fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(api.Path(), fileinfo.Size(), stats.FileRequiredResultOK)
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

// Extract returns a list of installed third party dependencies in a Go binary.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var readerAt io.ReaderAt
	if fileWithReaderAt, ok := input.Reader.(io.ReaderAt); ok {
		readerAt = fileWithReaderAt
	} else {
		buf := bytes.NewBuffer([]byte{})
		_, err := io.Copy(buf, input.Reader)
		if err != nil {
			return inventory.Inventory{}, err
		}
		readerAt = bytes.NewReader(buf.Bytes())
	}

	binfo, err := buildinfo.Read(readerAt)
	if err != nil {
		log.Debugf("error parsing the contents of Go binary (%s) for extraction: %v", input.Path, err)
		e.reportFileExtracted(input.Path, input.Info, err)
		return inventory.Inventory{}, nil
	}

	pkg := e.extractPackagesFromBuildInfo(binfo, input.Path)
	mainPkg := mainModule(binfo, input.Path)
	if mainPkg != nil {
		if mainPkg.Version == devel && e.VersionFromContent {
			if version := extractVersionFromConent(input.Reader); version != "" {
				mainPkg.Version = version
			}
		}
		pkg = append(pkg, mainPkg)
	}
	e.reportFileExtracted(input.Path, input.Info, nil)
	return inventory.Inventory{Packages: pkg}, nil
}

func (e Extractor) reportFileExtracted(path string, fileinfo fs.FileInfo, err error) {
	if e.stats == nil {
		return
	}
	var fileSizeBytes int64
	if fileinfo != nil {
		fileSizeBytes = fileinfo.Size()
	}
	e.stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
		Path:          path,
		Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
		FileSizeBytes: fileSizeBytes,
	})
}

func (e *Extractor) extractPackagesFromBuildInfo(binfo *buildinfo.BuildInfo, filename string) []*extractor.Package {
	res := []*extractor.Package{}

	validatedGoVers, err := validateGoVersion(binfo.GoVersion)
	if err != nil {
		log.Warnf("failed to validate the Go version from buildinfo (%v): %v", binfo, err)
	}
	if validatedGoVers != "" {
		res = append(res, &extractor.Package{
			Name:      "go",
			Version:   validatedGoVers,
			PURLType:  purl.TypeGolang,
			Locations: []string{filename},
		})
	}

	for _, dep := range binfo.Deps {
		pkgName, pkgVers := parseDependency(dep)
		if pkgName == "" {
			continue
		}

		pkgVers = strings.TrimPrefix(pkgVers, "v")

		pkg := &extractor.Package{
			Name:      pkgName,
			Version:   pkgVers,
			PURLType:  purl.TypeGolang,
			Locations: []string{filename},
		}
		res = append(res, pkg)
	}

	return res
}

func validateGoVersion(vers string) (string, error) {
	if vers == "" {
		return "", errors.New("can't validate empty Go version")
	}

	// The Go version can have multiple parts, in particular for development
	// versions of Go. The actual Go version should be the first part (e.g.
	// 'go1.20-pre3 +a813be86df' -> 'go1.20-pre3')
	goVersion := strings.Split(vers, " ")[0]

	// Strip the "go" prefix from the Go version. (e.g. go1.16.3 => 1.16.3)
	res := strings.TrimPrefix(goVersion, "go")
	return res, nil
}

func parseDependency(d *debug.Module) (string, string) {
	dep := d
	// Handle module replacement, but don't replace module if the replacement
	// doesn't have a package name.
	if dep.Replace != nil && dep.Replace.Path != "" {
		dep = dep.Replace
	}

	return dep.Path, dep.Version
}

func mainModule(binfo *buildinfo.BuildInfo, filename string) *extractor.Package {
	if binfo.Main.Path == "" {
		return nil
	}
	version := strings.TrimPrefix(binfo.Main.Version, "v")
	return &extractor.Package{
		Name:      binfo.Main.Path,
		Version:   version,
		PURLType:  purl.TypeGolang,
		Locations: []string{filename},
	}
}

func extractVersionFromConent(reader io.Reader) string {
	buf := bytes.NewBuffer([]byte{})
	if _, err := io.Copy(buf, reader); err != nil {
		return ""
	}
	matches := reVersion.FindSubmatch(buf.Bytes())
	if len(matches) == 0 {
		return ""
	}

	var version string
	for i, name := range reVersion.SubexpNames() {
		if name == "version" {
			version = string(matches[i])
			log.Infof("name: %q, matches[i]: %q", name, matches[i])
		}
	}

	version = strings.TrimPrefix(version, "v")
	return version
}
