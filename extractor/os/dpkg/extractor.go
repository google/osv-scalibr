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

// Package dpkg extracts packages from dpkg database.
package dpkg

import (
	"bufio"
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
	"github.com/google/osv-scalibr/extractor/os/osrelease"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/dpkg"

	// defaultMaxFileSize is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSize = 100 * units.MiB
)

// Config is the configuration for the Extractor.
type Config struct {
	// MaxFileSize is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	MaxFileSize int64
}

// DefaultConfig returns the default configuration for the DPKG extractor.
func DefaultConfig() Config {
	return Config{
		MaxFileSize: defaultMaxFileSize,
	}
}

// Extractor extracts packages from DPKG files.
type Extractor struct {
	maxFileSize int64
}

// New returns a DPKG extractor.
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

// FileRequired returns true if the specified file matches dpkg status file pattern.
func (e Extractor) FileRequired(path string, _ fs.FileMode) bool {
	// For Windows
	path = filepath.ToSlash(path)

	// Matches the status file.
	if path == "var/lib/dpkg/status" {
		return true
	}

	// Matches all files in status.d.
	if strings.HasPrefix(path, "var/lib/dpkg/status.d/") {
		return true
	}

	return false
}

// Extract extracts packages from dpkg status files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *extractor.ScanInput) ([]*extractor.Inventory, error) {
	if input.Info != nil && input.Info.Size() > e.maxFileSize {
		return nil, fmt.Errorf("DPKG status file %s is too large: %d", input.Path, input.Info.Size())
	}
	m, err := osrelease.GetOSRelease(input.ScanRoot)
	if err != nil {
		log.Errorf("osrelease.ParseOsRelease(): %v", err)
	}

	rd := textproto.NewReader(bufio.NewReader(input.Reader))
	pkgs := []*extractor.Inventory{}
	for eof := false; !eof; {
		// Return if canceled or exceeding deadline.
		if err := ctx.Err(); err != nil {
			return pkgs, fmt.Errorf("%s halted at %q because of context error: %v", e.Name(), input.Path, err)
		}

		h, err := rd.ReadMIMEHeader()
		if err != nil {
			if errors.Is(err, io.EOF) {
				// We might still have one more line of data
				// so return only after it's been parsed.
				eof = true
			} else {
				return pkgs, err
			}
		}
		// Distroless distributions have their packages in status.d, which does not contain the Status
		// value.
		if !strings.Contains(input.Path, "status.d") || h.Get("Status") != "" {
			installed, err := statusInstalled(h.Get("Status"))
			if err != nil {
				return pkgs, fmt.Errorf("statusInstalled(%q): %w", h.Get("Status"), err)
			}
			if !installed {
				continue
			}
		}
		pkgName := h.Get("Package")
		pkgVersion := h.Get("Version")
		if pkgName == "" || pkgVersion == "" {
			if !eof { // Expected when reaching the last line.
				log.Warnf("DPKG package name or version is empty (name: %q, version: %q)", pkgName, pkgVersion)
			}
			continue
		}
		maintainer := h.Get("Maintainer")
		arch := h.Get("Architecture")

		i := &extractor.Inventory{
			Name:    pkgName,
			Version: pkgVersion,
			Metadata: &Metadata{
				PackageName:       pkgName,
				PackageVersion:    pkgVersion,
				OSID:              m["ID"],
				OSVersionCodename: m["VERSION_CODENAME"],
				OSVersionID:       m["VERSION_ID"],
				Maintainer:        maintainer,
				Architecture:      arch,
			},
			Locations: []string{input.Path},
			Extractor: e.Name(),
		}
		sourceName, sourceVersion, err := parseSourceNameVersion(h.Get("Source"))
		if err != nil {
			return pkgs, fmt.Errorf("parseSourceNameVersion(%q): %w", h.Get("Source"), err)
		}
		if sourceName != "" {
			i.Metadata.(*Metadata).SourceName = sourceName
			i.Metadata.(*Metadata).SourceVersion = sourceVersion
		}

		pkgs = append(pkgs, i)
	}
	return pkgs, nil
}

func statusInstalled(status string) (bool, error) {
	// Status field format: "want flag status", e.g. "install ok installed"
	// The package is currently installed if the status field is set to installed.
	// Other fields just show the intent of the package manager but not the current state.
	parts := strings.Split(status, " ")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid DPKG Status field %q", status)
	}
	return parts[2] == "installed", nil
}

func parseSourceNameVersion(source string) (string, string, error) {
	if source == "" {
		return "", "", nil
	}
	// Format is either "name" or "name (version)"
	if idx := strings.Index(source, " ("); idx != -1 {
		if !strings.HasSuffix(source, ")") {
			return "", "", fmt.Errorf("Invalid DPKG Source field: %q", source)
		}
		n := source[:idx]
		v := source[idx+2 : len(source)-1]
		return n, v, nil
	}
	return source, "", nil
}

func toNamespace(m *Metadata) string {
	if m.OSID != "" {
		return m.OSID
	}
	log.Errorf("os-release[ID] not set, fallback to 'linux'")
	// TODO(b/298152210): Implement metric
	return "linux"
}

func toDistro(m *Metadata) string {
	// e.g. jammy
	if m.OSVersionCodename != "" {
		return m.OSVersionCodename
	}
	// fallback: e.g. 22.04
	if m.OSVersionID != "" {
		log.Warnf("VERSION_CODENAME not set in os-release, fallback to VERSION_ID")
		return m.OSVersionID
	}
	log.Errorf("VERSION_CODENAME and VERSION_ID not set in os-release")
	return ""
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	m := i.Metadata.(*Metadata)
	q := map[string]string{}
	distro := toDistro(m)
	if distro != "" {
		q[purl.Distro] = distro
	}
	if m.SourceName != "" {
		q[purl.Source] = m.SourceName
	}
	if m.Architecture != "" {
		q[purl.Arch] = m.Architecture
	}
	return &purl.PackageURL{
		Type:       purl.TypeDebian,
		Name:       m.PackageName,
		Namespace:  toNamespace(m),
		Version:    i.Version,
		Qualifiers: purl.QualifiersFromMap(q),
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }
