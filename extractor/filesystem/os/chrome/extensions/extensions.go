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
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// Name is the name for the RPM extractor
const Name = "chrome/extensions"

type manifest struct {
	Author struct {
		Email string `json:"email"`
	} `json:"author"`
	Background struct {
		ServiceWorker string `json:"service_worker"`
	} `json:"background"`
	ContentCapabilities struct {
		Matches     []string `json:"matches"`
		Permissions []string `json:"permissions"`
	} `json:"content_capabilities"`
	ContentSecurityPolicy struct {
		ExtensionPages string `json:"extension_pages"`
	} `json:"content_security_policy"`
	DefaultLocale           string `json:"default_locale"`
	Description             string `json:"description"`
	DifferentialFingerprint string `json:"differential_fingerprint"`
	ExternallyConnectable   struct {
		Matches []string `json:"matches"`
	} `json:"externally_connectable"`
	HostPermissions      []string          `json:"host_permissions"`
	Icons                map[string]string `json:"icons"`
	Key                  string            `json:"key"`
	ManifestVersion      int               `json:"manifest_version"`
	MinimumChromeVersion string            `json:"minimum_chrome_version"`
	Name                 string            `json:"name"`
	Permissions          []string          `json:"permissions"`
	Storage              struct {
		ManagedSchema string `json:"managed_schema"`
	} `json:"storage"`
	UpdateURL              string `json:"update_url"`
	Version                string `json:"version"`
	WebAccessibleResources []struct {
		Matches   []string `json:"matches"`
		Resources []string `json:"resources"`
	} `json:"web_accessible_resources"`
}

type message struct {
	Description string `json:"description"`
	Message     string `json:"message"`
}

type extensionMessages struct {
	ExtDesc message `json:"extDesc"`
	ExtName message `json:"extName"`
}

// Extractor extracts chrome extensions
type Extractor struct{}

// New returns an chrome extractor.
func New() *Extractor {
	return &Extractor{}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// todo: check this
// FileRequired returns true if the file is chrome manifest extension
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	path = filepath.ToSlash(path)

	if !strings.HasSuffix(path, "manifest.json") {
		return false
	}

	// todo: can I actually use this?
	switch runtime.GOOS {
	case "windows":
		// C:\Users\<Your_User_Name>\AppData\Local\Google\Chrome\User Data\Default\Extensions
		return strings.Contains(path, "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions")
	case "linux":
		// ~/.config/google-chrome/Default/Extensions/
		return strings.Contains(path, "/.config/google-chrome/Default/Extensions/")
	case "macos":
		// ~/Library/Application\ Support/Google/Chrome/Default/Extensions
		return strings.Contains(path, "/Library/Application Support/Google/Chrome/Default/Extensions")
	default:
		return false
	}
}

// Extract extracts chrome extensions
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var m manifest
	if err := json.NewDecoder(input.Reader).Decode(&m); err != nil {
		return nil, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}
	if m.Name == "" || m.Version == "" {
		return nil, fmt.Errorf("bad format %s", input.Path)
	}

	path, err := filepath.Abs(input.Path)
	if err != nil {
		return nil, fmt.Errorf("could not extract full path of %s: %w", input.Path, err)
	}
	parts := strings.Split(filepath.ToSlash(path), "/")
	if len(parts) < 3 {
		return nil, fmt.Errorf("could not extract extension ID from %s", path)
	}
	ID := parts[len(parts)-3]

	// https://groups.google.com/a/chromium.org/g/chromium-apps/c/kjbbarpEVKU
	if m.Name == "__MSG_extName__" || m.Description == "__MSG_extDesc__" {
		localInfo, err := extractLocalInfo(input, m.DefaultLocale)
		if err != nil {
			return nil, fmt.Errorf("could not extract locale info from %s: %w", input.Path, err)
		}
		if m.Name == "__MSG_extName__" {
			m.Name = localInfo.ExtName.Message
		}
		if m.Description == "__MSG_extDesc__" {
			m.Description = localInfo.ExtDesc.Message
		}
	}

	ivs := []*extractor.Inventory{
		{
			Name:    ID,
			Version: m.Version,
			Metadata: Metadata{
				AuthorEmail:          m.Author.Email,
				Description:          m.Description,
				HostPermissions:      m.HostPermissions,
				ManifestVersion:      m.ManifestVersion,
				MinimumChromeVersion: m.MinimumChromeVersion,
				Name:                 m.Name,
				Permissions:          m.Permissions,
				UpdateURL:            m.UpdateURL,
				Version:              m.Version,
			},
		},
	}

	return ivs, nil
}

func extractLocalInfo(input *filesystem.ScanInput, defaultLocale string) (*extensionMessages, error) {
	locale := defaultLocale
	if locale == "" {
		locale = "en_US"
	}

	messagePath := filepath.Join(filepath.Dir(input.Path), "/_locales/", defaultLocale, "message.json")

	f, err := input.FS.Open(messagePath)
	if err != nil {
		return nil, err
	}

	var m extensionMessages
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		return nil, fmt.Errorf("could not read %s: %w", input.Path, err)
	}

	return &m, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL { return nil }

// todo: check this
// Ecosystem is not defined.
func (Extractor) Ecosystem(i *extractor.Inventory) string { return "" }
