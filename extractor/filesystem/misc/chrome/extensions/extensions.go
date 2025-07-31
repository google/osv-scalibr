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

// Package extensions extracts chrome extensions.
package extensions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// Name is the name for the Chrome extensions extractor
const Name = "chrome/extensions"

var (
	windowsChromeExtensionsPattern   = regexp.MustCompile(`(?m)\/Google\/Chrome(?: Beta| SxS| for Testing|)\/User Data\/Default\/Extensions\/[a-p]{32}\/[^\/]+\/manifest\.json$`)
	windowsChromiumExtensionsPattern = regexp.MustCompile(`(?m)\/Chromium\/User Data\/Default\/Extensions\/[a-p]{32}\/[^\/]+\/manifest\.json$`)

	macosChromeExtensionsPattern   = regexp.MustCompile(`(?m)\/Google\/Chrome(?: Beta| SxS| for Testing| Canary|)\/Default\/Extensions\/[a-p]{32}\/[^\/]+\/manifest\.json$`)
	macosChromiumExtensionsPattern = regexp.MustCompile(`(?m)\/Chromium\/Default\/Extensions\/[a-p]{32}\/[^\/]+\/manifest\.json$`)

	linuxChromeExtensionsPattern   = regexp.MustCompile(`(?m)\/google-chrome(?:-beta|-unstable|-for-testing|)\/Default\/Extensions\/[a-p]{32}\/[^\/]+\/manifest\.json$`)
	linuxChromiumExtensionsPattern = regexp.MustCompile(`(?m)\/chromium\/Default\/Extensions\/[a-p]{32}\/[^\/]+\/manifest\.json$`)
)

type manifest struct {
	Author struct {
		Email string `json:"email"`
	} `json:"author"`
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

// Extractor extracts chrome extensions
type Extractor struct{}

// New returns an chrome extractor.
func New() filesystem.Extractor {
	return &Extractor{}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		RunningSystem: true,
	}
}

// FileRequired returns true if the file is chrome manifest extension
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	path = filepath.ToSlash(path)

	// pre-check to improve performances
	if !strings.HasSuffix(path, "manifest.json") {
		return false
	}

	switch runtime.GOOS {
	case "windows":
		return windowsChromeExtensionsPattern.MatchString(path) || windowsChromiumExtensionsPattern.MatchString(path)
	case "linux":
		return linuxChromeExtensionsPattern.MatchString(path) || linuxChromiumExtensionsPattern.MatchString(path)
	case "darwin":
		return macosChromeExtensionsPattern.MatchString(path) || macosChromiumExtensionsPattern.MatchString(path)
	default:
		return false
	}
}

// Extract extracts chrome extensions
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var m manifest
	if err := json.NewDecoder(input.Reader).Decode(&m); err != nil {
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
//	/extensionID/version/manifest.json
func extractExtensionsIDFromPath(input *filesystem.ScanInput) (string, error) {
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
	messagePath := filepath.Join(filepath.Dir(input.Path), "_locales", m.DefaultLocale, "message.json")
	messagePath = filepath.ToSlash(messagePath)

	f, err := input.FS.Open(messagePath)
	if err != nil {
		return err
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
