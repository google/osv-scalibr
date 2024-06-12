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

// Package gobinary extracts packages from buildinfo inside go binaries files.
package gobinary

import (
	"context"
	"debug/buildinfo"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "go/binary"
)

// Extractor extracts packages from buildinfo inside go binaries files.
type Extractor struct{}

type packageJSON struct {
	Version string `json:"version"`
	Name    string `json:"name"`
}

const permissiveVersionParsing = true

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// FileRequired returns true if the specified file is marked executable.
func (e Extractor) FileRequired(path string, fileinfo fs.FileInfo) bool {
	if !fileinfo.Mode().IsRegular() {
		// Includes dirs, symlinks, sockets, pipes...
		return false
	}

	// TODO(b/279138598): Research: Maybe on windows all files have the executable bit set.

	// Either windows .exe or unix executable bit is set.
	return filepath.Ext(path) == ".exe" || fileinfo.Mode()&0111 != 0
}

// Extract returns a list of installed third party dependencies in a Go binary.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	binfo, err := buildinfo.Read(input.Reader.(io.ReaderAt))
	if err != nil {
		log.Debugf("error parsing the contents of Go binary (%s) for extraction: %v", input.Path, err)
		return []*extractor.Inventory{}, nil
	}
	return e.extractPackagesFromBuildInfo(binfo, input.Path)
}

func (e *Extractor) extractPackagesFromBuildInfo(binfo *buildinfo.BuildInfo, filename string) ([]*extractor.Inventory, error) {
	res := []*extractor.Inventory{}

	validatedGoVers, err := validateGoVersion(binfo.GoVersion)
	if err != nil {
		log.Warnf("failed to validate the Go version from buildinfo (%v): %v", binfo, err)
	}
	if validatedGoVers != "" {
		res = append(res, &extractor.Inventory{
			Name:      "go",
			Version:   validatedGoVers,
			Locations: []string{filename},
		})
	}

	for _, dep := range binfo.Deps {
		pkgName, pkgVers := parseDependency(dep)
		if pkgName == "" {
			continue
		}

		pkgVers = strings.TrimPrefix(pkgVers, "v")

		pkg := &extractor.Inventory{
			Name:      pkgName,
			Version:   pkgVers,
			Locations: []string{filename},
		}
		res = append(res, pkg)
	}

	return res, nil
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

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return &purl.PackageURL{
		Type:    purl.TypeGolang,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }
