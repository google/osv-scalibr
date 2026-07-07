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
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	scalibrfs "github.com/google/osv-scalibr/fs"
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

	// maxJSONHeaderBytes caps the ASAR header JSON to 100 MiB to protect
	// against malicious/corrupted archives with an inflated jsonLen field.
	maxJSONHeaderBytes = 100 * units.MiB

	// maxPackageJSONBytes caps individual package.json reads to 10 MiB.
	maxPackageJSONBytes = 10 * units.MiB
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

	ra, err := scalibrfs.NewReaderAt(input.Reader)
	if err != nil {
		return nil, fmt.Errorf("%s: creating ReaderAt for %q: %w", e.Name(), input.Path, err)
	}

	var pkgs []*extractor.Package
	for pkgName, pkgNode := range nmNode.Files {
		pkgs = append(pkgs,
			e.extractFromNodeModulesEntry(ra, pkgName, pkgNode, dataOffset, input.Path)...)
	}
	return pkgs, nil
}

// extractFromNodeModulesEntry handles a single entry inside a node_modules
// directory. It accounts for two layouts:
//
//  1. Regular packages: node_modules/<name>/package.json
//  2. Scoped packages:  node_modules/@scope/<name>/package.json
//
// For scoped packages the top-level entry (e.g. "@types") is itself a
// directory whose children are the real package directories. We detect this
// by checking whether the entry name starts with "@" and, if so, recurse one
// level deeper.
func (e Extractor) extractFromNodeModulesEntry(
	ra io.ReaderAt, entryName string, node asarNode, dataOffset int64, asarPath string,
) []*extractor.Package {
	// Scoped package namespace directory (e.g. "@types", "@babel").
	if strings.HasPrefix(entryName, "@") {
		var pkgs []*extractor.Package
		for scopedName, scopedNode := range node.Files {
			fullName := entryName + "/" + scopedName
			pkgs = append(pkgs,
				e.extractPackageJSONNode(ra, fullName, scopedNode, dataOffset, asarPath)...)
		}
		return pkgs
	}

	return e.extractPackageJSONNode(ra, entryName, node, dataOffset, asarPath)
}

// extractPackageJSONNode reads the package.json directly inside the given
// asarNode (expected to be a package directory) and returns a Package if the
// file is valid and contains both name and version.
func (e Extractor) extractPackageJSONNode(
	ra io.ReaderAt, pkgName string, pkgNode asarNode, dataOffset int64, asarPath string,
) []*extractor.Package {
	pjNode, ok := pkgNode.Files["package.json"]
	if !ok {
		return nil
	}
	pj, err := readPackageJSON(ra, pjNode, dataOffset)
	if err != nil {
		log.Warnf("%s: reading package.json for %q in %q: %v",
			e.Name(), pkgName, asarPath, err)
		return nil
	}
	if pj.Name == "" || pj.Version == "" {
		return nil
	}
	return []*extractor.Package{{
		Name:     pj.Name,
		Version:  pj.Version,
		PURLType: purl.TypeNPM,
		Location: extractor.LocationFromPath(asarPath),
	}}
}

// asarPrefix is the 16-byte binary header at the start of every ASAR file.
//
// ASAR layout (all uint32 little-endian):
//
//	[4B: 8]  [4B: headerPickleSize]   <- first Pickle (8 bytes total)
//	[4B: headerPickleSize] [4B: jsonLen] [jsonLen bytes JSON] [padding]
//	                                   <- second Pickle
//	[file data ...]
type asarPrefix struct {
	_                uint32 // always 8 (size of first Pickle payload)
	HeaderPickleSize uint32
	_                uint32 // mirrors HeaderPickleSize
	JSONLen          uint32
}

// readHeader reads and parses the ASAR Pickle-encoded header.
// It returns the parsed header and the absolute byte offset at which file
// data begins (i.e. the end of the header region).
func readHeader(r io.Reader) (asarHeader, int64, error) {
	var prefix asarPrefix
	if err := binary.Read(r, binary.LittleEndian, &prefix); err != nil {
		return asarHeader{}, 0, fmt.Errorf("reading ASAR prefix: %w", err)
	}

	headerPickleSize := int64(prefix.HeaderPickleSize)
	jsonLen := int64(prefix.JSONLen)

	if jsonLen <= 0 || jsonLen > headerPickleSize {
		return asarHeader{}, 0, fmt.Errorf(
			"invalid ASAR header sizes: pickle=%d json=%d",
			headerPickleSize, jsonLen)
	}
	if jsonLen > maxJSONHeaderBytes {
		return asarHeader{}, 0, fmt.Errorf(
			"ASAR header JSON too large: %d bytes", jsonLen)
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
// data region. r must implement io.ReaderAt.
func readPackageJSON(
	r io.ReaderAt, node asarNode, dataOffset int64,
) (packageJSON, error) {
	var fileOffset int64
	if _, err := fmt.Sscanf(node.Offset, "%d", &fileOffset); err != nil {
		return packageJSON{}, fmt.Errorf("parsing file offset %q: %w",
			node.Offset, err)
	}

	if node.Size <= 0 || node.Size > maxPackageJSONBytes {
		return packageJSON{}, fmt.Errorf("package.json size out of range: %d", node.Size)
	}

	buf := make([]byte, node.Size)
	if _, err := r.ReadAt(buf, dataOffset+fileOffset); err != nil {
		return packageJSON{}, fmt.Errorf("reading package.json bytes: %w", err)
	}

	var pj packageJSON
	if err := json.Unmarshal(buf, &pj); err != nil {
		return packageJSON{}, fmt.Errorf("parsing package.json: %w", err)
	}
	return pj, nil
}
