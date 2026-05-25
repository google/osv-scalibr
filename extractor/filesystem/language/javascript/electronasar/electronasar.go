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

// Package electronasar extracts npm packages bundled inside Electron ASAR
// archives (resources/app.asar).
package electronasar

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/electronasar"

	// defaultMaxFileSizeBytes is the maximum .asar file size to attempt parsing.
	defaultMaxFileSizeBytes = 500 * units.MiB

	// asarHeaderOffset is the byte offset at which the JSON header string begins.
	// Layout: [4B pickle size of header_size][4B header_size value]
	//         [4B pickle size of header][4B header JSON length] = 16 bytes total.
	asarHeaderOffset = 16
)

// asarHeader is the top-level JSON structure of an ASAR archive header.
type asarHeader struct {
	Files map[string]asarNode `json:"files"`
}

// asarNode represents a file or directory entry in the ASAR header tree.
type asarNode struct {
	Files  map[string]asarNode `json:"files"`
	Offset string              `json:"offset"`
	Size   int64               `json:"size"`
}

// packageJSON holds the fields we need from a bundled package.json.
type packageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Extractor extracts npm packages from Electron ASAR archives.
type Extractor struct {
	maxFileSizeBytes int64
}

// New returns an Electron ASAR extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}
	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true for files named app.asar inside a resources/
// directory, matching the Electron installation layout on all platforms.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := filepath.ToSlash(api.Path())
	if filepath.Base(path) != "app.asar" {
		return false
	}
	if !strings.Contains(strings.ToLower(path), "resources/") {
		return false
	}
	if e.maxFileSizeBytes > 0 {
		fileinfo, err := api.Stat()
		if err == nil && fileinfo != nil &&
			fileinfo.Size() > e.maxFileSizeBytes {
			return false
		}
	}
	return true
}

// Extract parses the ASAR header and yields one Package per bundled npm
// dependency found under node_modules/*/package.json.
func (e Extractor) Extract(
	ctx context.Context, input *filesystem.ScanInput,
) (inventory.Inventory, error) {
	pkgs, err := e.extractPackages(input)
	if err != nil {
		return inventory.Inventory{}, err
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

func (e Extractor) extractPackages(
	input *filesystem.ScanInput,
) ([]*extractor.Package, error) {
	hdr, dataOffset, err := readHeader(input.Reader)
	if err != nil {
		return nil, fmt.Errorf("%s: reading ASAR header from %q: %w",
			e.Name(), input.Path, err)
	}

	nmNode, ok := hdr.Files["node_modules"]
	if !ok {
		return nil, nil
	}

	var pkgs []*extractor.Package
	for pkgName, pkgNode := range nmNode.Files {
		pjNode, ok := pkgNode.Files["package.json"]
		if !ok {
			continue
		}
		pj, err := readPackageJSON(input.Reader, pjNode, dataOffset)
		if err != nil {
			log.Warnf("%s: reading package.json for %q in %q: %v",
				e.Name(), pkgName, input.Path, err)
			continue
		}
		if pj.Name == "" || pj.Version == "" {
			continue
		}
		pkgs = append(pkgs, &extractor.Package{
			Name:     pj.Name,
			Version:  pj.Version,
			PURLType: purl.TypeNPM,
			Location: extractor.LocationFromPath(input.Path),
		})
	}
	return pkgs, nil
}

// readHeader reads and parses the ASAR Pickle-encoded header.
// It returns the parsed header and the absolute byte offset at which file
// data begins (i.e. the end of the header region).
//
// ASAR layout (all uint32 little-endian):
//
//	[4B: 8]  [4B: headerPickleSize]   <- first Pickle (8 bytes total)
//	[4B: headerPickleSize] [4B: jsonLen] [jsonLen bytes JSON] [padding]
//	                                   <- second Pickle
//	[file data ...]
func readHeader(r io.Reader) (asarHeader, int64, error) {
	var buf [asarHeaderOffset]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return asarHeader{}, 0, fmt.Errorf("reading ASAR prefix: %w", err)
	}

	// bytes 4-7: size of the header Pickle object (payload only, includes
	// the 4-byte jsonLen field that precedes the JSON bytes).
	headerPickleSize := int64(binary.LittleEndian.Uint32(buf[4:8]))
	// bytes 12-15: length of the JSON string.
	jsonLen := int64(binary.LittleEndian.Uint32(buf[12:16]))

	if jsonLen <= 0 || jsonLen > headerPickleSize {
		return asarHeader{}, 0, fmt.Errorf(
			"invalid ASAR header sizes: pickle=%d json=%d",
			headerPickleSize, jsonLen)
	}

	jsonBuf := make([]byte, jsonLen)
	if _, err := io.ReadFull(r, jsonBuf); err != nil {
		return asarHeader{}, 0, fmt.Errorf("reading ASAR header JSON: %w", err)
	}

	var hdr asarHeader
	if err := json.Unmarshal(jsonBuf, &hdr); err != nil {
		return asarHeader{}, 0, fmt.Errorf("parsing ASAR header JSON: %w", err)
	}

	// Data starts after the first Pickle (8 bytes), the second Pickle's
	// 4-byte size field, and the headerPickleSize bytes of payload.
	dataOffset := int64(12) + headerPickleSize
	return hdr, dataOffset, nil
}

// readPackageJSON reads and parses a package.json file stored inside the ASAR
// data region. r must implement io.ReadSeeker.
func readPackageJSON(
	r io.Reader, node asarNode, dataOffset int64,
) (packageJSON, error) {
	rs, ok := r.(io.ReadSeeker)
	if !ok {
		return packageJSON{}, errors.New("reader does not implement io.ReadSeeker")
	}

	var fileOffset int64
	if _, err := fmt.Sscanf(node.Offset, "%d", &fileOffset); err != nil {
		return packageJSON{}, fmt.Errorf("parsing file offset %q: %w",
			node.Offset, err)
	}

	if _, err := rs.Seek(dataOffset+fileOffset, io.SeekStart); err != nil {
		return packageJSON{}, fmt.Errorf("seeking to package.json: %w", err)
	}

	buf := make([]byte, node.Size)
	if _, err := io.ReadFull(rs, buf); err != nil {
		return packageJSON{}, fmt.Errorf("reading package.json bytes: %w", err)
	}

	var pj packageJSON
	if err := json.Unmarshal(buf, &pj); err != nil {
		return packageJSON{}, fmt.Errorf("parsing package.json: %w", err)
	}
	return pj, nil
}
