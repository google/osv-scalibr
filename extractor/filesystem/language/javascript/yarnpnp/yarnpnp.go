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

// Package yarnpnp extracts packages from Yarn Plug'n'Play files.
package yarnpnp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/yarnpnp"
)

type pnpData struct {
	PackageRegistryData []json.RawMessage `json:"packageRegistryData"`
}

// Extractor extracts packages from Yarn Plug'n'Play files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e *Extractor) Name() string { return Name }

// Version of the extractor.
func (e *Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e *Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true for Yarn Plug'n'Play data and loader files.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	base := filepath.Base(path)
	if base != ".pnp.cjs" && base != ".pnp.data.json" {
		return false
	}

	dir := filepath.ToSlash(filepath.Dir(path))
	return !slices.Contains(strings.Split(dir, "/"), "node_modules")
}

// Extract extracts packages from a Yarn Plug'n'Play file.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	reader := input.Reader
	if filepath.Base(input.Path) == ".pnp.cjs" {
		data, found, err := readInlineData(ctx, reader)
		if err != nil {
			return inventory.Inventory{}, fmt.Errorf("could not extract %q: %w", input.Path, err)
		}
		if !found {
			// When inlining is disabled, the runtime state is stored in the
			// separately scanned .pnp.data.json file.
			return inventory.Inventory{Packages: []*extractor.Package{}}, nil
		}
		reader = bytes.NewReader(data)
	}

	packages, err := parseData(ctx, reader, input.Path)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract %q: %w", input.Path, err)
	}
	return inventory.Inventory{Packages: packages}, nil
}

func parseData(ctx context.Context, r io.Reader, path string) ([]*extractor.Package, error) {
	var data pnpData
	if err := json.NewDecoder(r).Decode(&data); err != nil {
		return nil, fmt.Errorf("parsing Plug'n'Play data: %w", err)
	}
	if data.PackageRegistryData == nil {
		return nil, errors.New("Plug'n'Play data is missing packageRegistryData")
	}

	packages := []*extractor.Package{}
	seen := make(map[string]struct{})
	for _, rawRegistryEntry := range data.PackageRegistryData {
		if err := ctx.Err(); err != nil {
			return packages, err
		}

		nameRaw, referencesRaw, err := decodePair(rawRegistryEntry)
		if err != nil {
			return nil, fmt.Errorf("invalid package registry entry: %w", err)
		}
		if bytes.Equal(bytes.TrimSpace(nameRaw), []byte("null")) {
			continue
		}

		var name string
		if err := json.Unmarshal(nameRaw, &name); err != nil {
			return nil, fmt.Errorf("invalid package name: %w", err)
		}
		if name == "" {
			return nil, errors.New("invalid empty package name")
		}

		var references []json.RawMessage
		if err := json.Unmarshal(referencesRaw, &references); err != nil {
			return nil, fmt.Errorf("invalid references for package %q: %w", name, err)
		}
		for _, rawReference := range references {
			referenceRaw, _, err := decodePair(rawReference)
			if err != nil {
				return nil, fmt.Errorf("invalid reference for package %q: %w", name, err)
			}
			if bytes.Equal(bytes.TrimSpace(referenceRaw), []byte("null")) {
				continue
			}

			var reference string
			if err := json.Unmarshal(referenceRaw, &reference); err != nil {
				return nil, fmt.Errorf("invalid reference for package %q: %w", name, err)
			}
			version, ok := npmVersion(reference)
			if !ok {
				continue
			}

			key := name + "\x00" + version
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			packages = append(packages, &extractor.Package{
				Name:     name,
				Version:  version,
				PURLType: purl.TypeNPM,
				Location: extractor.LocationFromPath(path),
			})
		}
	}
	return packages, nil
}

func decodePair(raw json.RawMessage) (json.RawMessage, json.RawMessage, error) {
	var pair []json.RawMessage
	if err := json.Unmarshal(raw, &pair); err != nil {
		return nil, nil, err
	}
	if len(pair) != 2 {
		return nil, nil, fmt.Errorf("got %d fields, want 2", len(pair))
	}
	return pair[0], pair[1], nil
}

func npmVersion(reference string) (string, bool) {
	for strings.HasPrefix(reference, "virtual:") {
		_, unwrapped, ok := strings.Cut(reference, "#")
		if !ok {
			return "", false
		}
		reference = unwrapped
	}

	if version, ok := strings.CutPrefix(reference, "npm:"); ok {
		return version, version != ""
	}

	patch, ok := strings.CutPrefix(reference, "patch:")
	if !ok {
		return "", false
	}
	locator, _, _ := strings.Cut(patch, "#")
	at := strings.LastIndex(locator, "@")
	if at < 0 {
		return "", false
	}
	underlying, err := url.PathUnescape(locator[at+1:])
	if err != nil {
		return "", false
	}
	return npmVersion(underlying)
}

func readInlineData(ctx context.Context, r io.Reader) ([]byte, bool, error) {
	reader := bufio.NewReader(r)
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		line, err := reader.ReadString('\n')
		if rawIndex := strings.Index(line, "const RAW_RUNTIME_STATE"); rawIndex >= 0 {
			equalsIndex := strings.Index(line[rawIndex:], "=")
			if equalsIndex < 0 {
				return nil, false, errors.New("invalid RAW_RUNTIME_STATE declaration")
			}
			rest := line[rawIndex+equalsIndex+1:]
			data, err := decodeJSString(ctx, io.MultiReader(strings.NewReader(rest), reader))
			return data, true, err
		}

		const jsonParseMarker = "hydrateRuntimeState(JSON.parse("
		if markerIndex := strings.Index(line, jsonParseMarker); markerIndex >= 0 {
			rest := strings.TrimLeft(line[markerIndex+len(jsonParseMarker):], " \t\r\n")
			if rest != "" && (rest[0] == '\'' || rest[0] == '"') {
				data, err := decodeJSString(ctx, io.MultiReader(strings.NewReader(rest), reader))
				return data, true, err
			}
		}

		if errors.Is(err, io.EOF) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
	}
}

func decodeJSString(ctx context.Context, r io.Reader) ([]byte, error) {
	reader := bufio.NewReader(r)
	quote, err := readQuote(reader)
	if err != nil {
		return nil, err
	}

	var result []byte
	for bytesRead := 0; ; bytesRead++ {
		if bytesRead%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}

		b, err := reader.ReadByte()
		if err != nil {
			return nil, errors.New("unterminated JavaScript string")
		}
		if b == quote {
			return result, nil
		}
		if b != '\\' {
			result = append(result, b)
			continue
		}

		escaped, err := reader.ReadByte()
		if err != nil {
			return nil, errors.New("unterminated JavaScript escape")
		}
		switch escaped {
		case '\n':
			continue
		case '\r':
			if next, err := reader.Peek(1); err == nil && next[0] == '\n' {
				_, _ = reader.ReadByte()
			}
			continue
		default:
			// Yarn escapes the serialized JSON for a JavaScript string. Removing
			// the JavaScript escape restores the original JSON byte.
			result = append(result, escaped)
		}
	}
}

func readQuote(reader *bufio.Reader) (byte, error) {
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return 0, errors.New("missing JavaScript string")
		}
		if b == '\'' || b == '"' {
			return b, nil
		}
		if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
			return 0, errors.New("runtime state is not a JavaScript string")
		}
	}
}

var _ filesystem.Extractor = (*Extractor)(nil)
