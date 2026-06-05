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

// Package extensions extracts Chrome, Chromium, Firefox and Edge extensions.
package extensions

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

// Name is the name for the browser extensions extractor
const Name = "browser/extensions"

var (
	windowsChromeExtensionsPattern   = regexp.MustCompile(`(?m)\/Google\/Chrome(?: Beta| SxS| for Testing|)\/User Data\/Default\/Extensions\/[a-p]{32}\/[^\/]+\/manifest\.json$`)
	windowsChromiumExtensionsPattern = regexp.MustCompile(`(?m)\/Chromium\/User Data\/Default\/Extensions\/[a-p]{32}\/[^\/]+\/manifest\.json$`)
	windowsFirefoxExtensionsPattern  = regexp.MustCompile(`(?m)\/Mozilla\/Firefox\/Profiles\/[^\/]+\/extensions\/[^\/]+\.xpi$`)
	windowsEdgeExtensionsPattern     = regexp.MustCompile(`(?m)\/Microsoft\/Edge(?: Beta| Dev| SxS|)\/User Data\/Default\/Extensions\/[a-p]{32}\/[^\/]+\/manifest\.json$`)

	macosChromeExtensionsPattern   = regexp.MustCompile(`(?m)\/Google\/Chrome(?: Beta| SxS| for Testing| Canary|)\/Default\/Extensions\/[a-p]{32}\/[^\/]+\/manifest\.json$`)
	macosChromiumExtensionsPattern = regexp.MustCompile(`(?m)\/Chromium\/Default\/Extensions\/[a-p]{32}\/[^\/]+\/manifest\.json$`)
	macosFirefoxExtensionsPattern  = regexp.MustCompile(`(?m)\/Library\/Application Support\/Firefox\/Profiles\/[^\/]+\/extensions\/[^\/]+\.xpi$`)
	macosEdgeExtensionsPattern     = regexp.MustCompile(`(?m)\/Library\/Application Support\/Microsoft Edge(?: Beta| Dev| Canary|)\/[^\/]+\/Extensions\/[a-p]{32}\/[^\/]+\/manifest\.json$`)

	linuxChromeExtensionsPattern   = regexp.MustCompile(`(?m)\/google-chrome(?:-beta|-unstable|-for-testing|)\/Default\/Extensions\/[a-p]{32}\/[^\/]+\/manifest\.json$`)
	linuxChromiumExtensionsPattern = regexp.MustCompile(`(?m)\/chromium\/Default\/Extensions\/[a-p]{32}\/[^\/]+\/manifest\.json$`)
	linuxFirefoxExtensionsPattern  = regexp.MustCompile(`(?m)(?:snap\/firefox\/common\/|\.var\/app\/org\.mozilla\.firefox\/|)\.mozilla\/firefox\/[^\/]+\/extensions\/[^\/]+\.xpi$`)
	linuxEdgeExtensionsPattern     = regexp.MustCompile(`(?m)\/\.config\/microsoft-edge(-beta|-dev|)\/[^\/]+\/Extensions\/[a-p]{32}\/[^\/]+\/manifest\.json$`)

	xpiContent []byte // Need to read twice for extracting locale case
)

type manifest struct {
	Author               Author   `json:"author"`
	DefaultLocale        string   `json:"default_locale"`
	Description          string   `json:"description"`
	HostPermissions      []string `json:"host_permissions"`
	ManifestVersion      int      `json:"manifest_version"`
	MinimumChromeVersion string   `json:"minimum_chrome_version"`
	Name                 string   `json:"name"`
	Permissions          []string `json:"permissions"`
	UpdateURL            string   `json:"update_url"`
	Version              string   `json:"version"`
}

// Author structs for unmarshalling Firefox manifests since it holds author as direct string value
type Author struct {
	Name  string
	Email string
}

// UnmarshalJSON is used for parsing Firefox and other browsers
func (a *Author) UnmarshalJSON(data []byte) error {
	// Try string first (Firefox)
	var name string
	if err := json.Unmarshal(data, &name); err == nil {
		a.Name = name
		return nil
	}

	// Fall back to object (Chrome/Edge)
	var obj struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	a.Email = obj.Email
	return nil
}

func (m *manifest) validate() error {
	if m.Name == "" {
		return errors.New("field 'Name' must be specified")
	}
	if m.Version == "" {
		return errors.New("field 'Version' must be specified")
	}
	return nil
}

type message struct {
	Description string `json:"description"`
	Message     string `json:"message"`
}

// Extractor extracts browser extensions
type Extractor struct{}

// New returns an browser extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 1 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		RunningSystem: true,
	}
}

// FileRequired returns true if the file is one of the supported browser extension files
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	path = filepath.ToSlash(path)

	// pre-check to improve performances
	if !(strings.HasSuffix(path, "manifest.json") || strings.HasSuffix(path, ".xpi")) {
		return false
	}

	switch runtime.GOOS {
	case "windows":
		return windowsChromeExtensionsPattern.MatchString(path) || windowsChromiumExtensionsPattern.MatchString(path) || windowsFirefoxExtensionsPattern.MatchString(path) || windowsEdgeExtensionsPattern.MatchString(path)
	case "linux":
		return linuxChromeExtensionsPattern.MatchString(path) || linuxChromiumExtensionsPattern.MatchString(path) || linuxFirefoxExtensionsPattern.MatchString(path) || linuxEdgeExtensionsPattern.MatchString(path)
	case "darwin":
		return macosChromeExtensionsPattern.MatchString(path) || macosChromiumExtensionsPattern.MatchString(path) || macosFirefoxExtensionsPattern.MatchString(path) || macosEdgeExtensionsPattern.MatchString(path)
	default:
		return false
	}
}

// Extract extracts browser extensions
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var ioReader io.Reader
	var err error
	if strings.HasSuffix(input.Path, "xpi") {
		xpiContent, err = io.ReadAll(input.Reader)
		if err != nil {
			return inventory.Inventory{}, fmt.Errorf("could not read XPI file: %w", err)
		}
		manifestContent, err := extractFileFromXPI("manifest.json")
		if err != nil {
			return inventory.Inventory{}, fmt.Errorf("could not extract manifest: %w", err)
		}
		ioReader = bytes.NewReader(manifestContent)
	} else {
		ioReader = input.Reader
	}

	var m manifest
	if err := json.NewDecoder(ioReader).Decode(&m); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract manifest: %w", err)
	}
	if err := m.validate(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("bad format in manifest: %w", err)
	}

	id, err := extractExtensionsIDFromPath(input)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract extension id: %w", err)
	}

	// if default locale is specified some fields of the manifest may be
	// written inside the ./_locales/LOCALE_CODE/messages.json file
	if m.DefaultLocale != "" {
		if err := extractLocaleInfo(&m, input); err != nil {
			return inventory.Inventory{}, fmt.Errorf("could not extract locale info: %w", err)
		}
	}

	return inventory.Inventory{Packages: []*extractor.Package{
		{
			Name:     id,
			Version:  m.Version,
			PURLType: purl.TypeGeneric,
			Metadata: &Metadata{
				AuthorEmail:          m.Author.Email,
				Author:               m.Author.Name,
				Description:          m.Description,
				HostPermissions:      m.HostPermissions,
				ManifestVersion:      m.ManifestVersion,
				MinimumChromeVersion: m.MinimumChromeVersion,
				Name:                 m.Name,
				Permissions:          m.Permissions,
				UpdateURL:            m.UpdateURL,
			},
		},
	}}, nil
}

// extractExtensionsIDFromPath extracts the extensions id from the path
//
// expected path is:
//
//	/extensionID/version/manifest.json for Chrome, Chromium and Edge
//
// For Firefox, it is the name of .xpi file, sometimes it is a email-style ID, and sometimes it is UUID-style ID
func extractExtensionsIDFromPath(input *filesystem.ScanInput) (string, error) {
	if strings.HasSuffix(input.Path, "xpi") {
		base := filepath.Base(input.Path) // "uBlock0@raymondhill.net.xpi"
		return strings.TrimSuffix(base, ".xpi"), nil
	}
	parts := strings.Split(filepath.ToSlash(input.Path), "/")
	if len(parts) < 3 {
		return "", errors.New("cold not find id expected path format '/extensionID/version/manifest.json'")
	}
	id := parts[len(parts)-3]
	// no more validation on the id is required since the path has been checked during FileRequired
	return id, nil
}

// extractLocaleInfo extract locale information from the _locales/LOCALE_CODE/messages.json
// following manifest.json v3 specification
func extractLocaleInfo(m *manifest, input *filesystem.ScanInput) error {
	var f io.Reader
	var err error
	if strings.HasSuffix(input.Path, "xpi") {
		messagePath := fmt.Sprintf("_locales/%s/messages.json", m.DefaultLocale)
		fileContent, err := extractFileFromXPI(messagePath)
		if err != nil {
			return err
		}
		f = bytes.NewReader(fileContent)
	} else {
		messagePath := filepath.Join(filepath.Dir(input.Path), "_locales", m.DefaultLocale, "messages.json")
		messagePath = filepath.ToSlash(messagePath)

		f, err = input.FS.Open(messagePath)
		if err != nil {
			return err
		}
	}

	// using a map to decode since the keys are determined by the values
	// of the manifest.json fields
	//
	// ex:
	//
	// 	manifest.json:
	// 	"name" : "__MSG_43ry328yr932__"
	// 	en/message.json
	// 	"43ry328yr932" : "Extension name"
	var messages map[string]message
	if err := json.NewDecoder(f).Decode(&messages); err != nil {
		return err
	}

	lowerCase := map[string]message{}
	for k, v := range messages {
		lowerCase[strings.ToLower(k)] = v
	}

	if v, ok := cutPrefixSuffix(m.Name, "__MSG_", "__"); ok {
		if msg, ok := lowerCase[strings.ToLower(v)]; ok {
			m.Name = msg.Message
		}
	}

	if v, ok := cutPrefixSuffix(m.Description, "__MSG_", "__"); ok {
		if msg, ok := lowerCase[strings.ToLower(v)]; ok {
			m.Description = msg.Message
		}
	}

	return nil
}

// cutPrefixSuffix cuts the specified prefix and suffix if they exist, returns false otherwise
func cutPrefixSuffix(s string, prefix string, suffix string) (string, bool) {
	if !strings.HasPrefix(s, prefix) {
		return "", false
	}
	if !strings.HasSuffix(s, suffix) {
		return "", false
	}
	s = s[len(prefix) : len(s)-len(suffix)]
	return s, true
}

// extractFileFromXPI extracts any file content from an XPI archieve in memory
func extractFileFromXPI(fileName string) ([]byte, error) {
	// Open as ZIP directly from the in-memory byte slice
	zipReader, err := zip.NewReader(bytes.NewReader(xpiContent), int64(len(xpiContent)))
	if err != nil {
		return nil, fmt.Errorf("failed to open xpi as zip: %w", err)
	}

	// Find manifest.json inside the archive
	for _, f := range zipReader.File {
		if f.Name != fileName {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open %s: %w", fileName, err)
		}
		defer rc.Close()

		manifestData, err := io.ReadAll(rc)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", fileName, err)
		}

		return manifestData, nil
	}

	return nil, fmt.Errorf("%s not found in xpi", fileName)
}
