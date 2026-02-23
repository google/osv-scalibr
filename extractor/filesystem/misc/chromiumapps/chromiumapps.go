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

// Package chromiumapps extracts Chromium-based application versions from
// well-known installation footprints.
package chromiumapps

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/micromdm/plist"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique identifier for this extractor.
	Name = "misc/chromiumapps"

	maxBinaryScanBytes = 8 << 20
	maxPlistReadBytes  = 2 << 20
)

var (
	knownFileNames = map[string]bool{
		"chrome.exe":         true,
		"chrome":             true,
		"msedge.exe":         true,
		"msedge":             true,
		"electron.exe":       true,
		"electron":           true,
		"electron.asar":      true,
		"electron framework": true,
	}

	versionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	appVersionPart = regexp.MustCompile(`^app-(\d+\.\d+\.\d+(?:\.\d+)?)$`)
	chromeToken    = regexp.MustCompile(`Chrome/(\d+\.\d+\.\d+\.\d+)`)
	electronToken  = regexp.MustCompile(`Electron/(\d+\.\d+\.\d+(?:\.\d+)?)`)
)

// Extractor implements filesystem.Extractor for Chromium-based applications.
type Extractor struct{}

// Metadata captures extraction details and version signals.
type Metadata struct {
	ChromiumVersion string
	ElectronVersion string
	VersionSource   string
}

// New returns an initialized Chromium apps extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{}, nil
}

// Name returns the extractor name.
func (e *Extractor) Name() string { return Name }

// Version returns the extractor implementation version.
func (e *Extractor) Version() int { return 0 }

// Requirements returns required capabilities for the extractor.
func (e *Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired reports whether the file path is a known Chromium app footprint.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	base := strings.ToLower(filepath.Base(filepath.ToSlash(api.Path())))
	return knownFileNames[base]
}

// Extract extracts package information from a Chromium app footprint path.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if ctx.Err() != nil {
		return inventory.Inventory{}, ctx.Err()
	}

	path := filepath.ToSlash(input.Path)
	base := strings.ToLower(filepath.Base(path))
	if !knownFileNames[base] {
		return inventory.Inventory{}, nil
	}

	pkgName := inferPackageName(path, base)
	if pkgName == "" {
		return inventory.Inventory{}, nil
	}

	chromiumVersion, electronVersion, _ := extractVersionsFromReader(input.Reader)
	pathVersion, hasPathVersion := extractVersion(path)

	md := &Metadata{
		ChromiumVersion: chromiumVersion,
		ElectronVersion: electronVersion,
	}
	version, ok := selectVersion(ctx, input.FS, path, pkgName, chromiumVersion, pathVersion, hasPathVersion, md)
	if !ok {
		return inventory.Inventory{}, nil
	}

	return inventory.Inventory{
		Packages: []*extractor.Package{{
			Name:      pkgName,
			Version:   version,
			PURLType:  purl.TypeGeneric,
			Locations: []string{path},
			Metadata:  md,
		}},
	}, nil
}

func inferPackageName(path string, base string) string {
	lowerPath := strings.ToLower(path)
	switch {
	case strings.Contains(lowerPath, "/microsoft/edge/"), strings.Contains(lowerPath, "/microsoft edge/"):
		return "microsoft-edge"
	case strings.Contains(lowerPath, "/chromium/"):
		return "chromium"
	case strings.Contains(lowerPath, "/google/chrome/"), strings.Contains(lowerPath, "/google-chrome/"):
		return "google-chrome"
	case strings.Contains(lowerPath, "electron framework.framework"), strings.Contains(lowerPath, "/electron/"), ((base == "electron.exe" || base == "electron" || base == "electron.asar" || base == "electron framework") && strings.Contains(lowerPath, "/resources/")):
		return "electron"
	default:
		return ""
	}
}

func selectVersion(ctx context.Context, fsys scalibrfs.FS, path string, pkgName string, chromiumVersion string, pathVersion string, hasPathVersion bool, md *Metadata) (string, bool) {
	if chromiumVersion != "" {
		md.VersionSource = "chromium_binary"
		return chromiumVersion, true
	}
	if hasPathVersion {
		md.VersionSource = "path"
		return pathVersion, true
	}
	if pkgName != "electron" {
		return "", false
	}
	if ctx.Err() != nil {
		return "", false
	}
	if plistPath, ok := electronFrameworkInfoPlistPath(path); ok {
		if electronVersion, ok := extractCFBundleVersion(fsys, plistPath); ok {
			md.ElectronVersion = electronVersion
			md.VersionSource = "plist_cf_bundle_version"
			return electronVersion, true
		}
	}
	return "", false
}

func extractVersion(path string) (string, bool) {
	parts := strings.Split(path, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		if versionPattern.MatchString(p) {
			return p, true
		}
		if m := appVersionPart.FindStringSubmatch(strings.ToLower(p)); len(m) == 2 {
			return m[1], true
		}
	}
	return "", false
}

func extractVersionsFromReader(r io.Reader) (string, string, bool) {
	if r == nil {
		return "", "", false
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxBinaryScanBytes))
	if err != nil {
		return "", "", false
	}
	chrome := ""
	electron := ""
	if m := chromeToken.FindSubmatch(raw); len(m) == 2 {
		chrome = string(m[1])
	}
	if m := electronToken.FindSubmatch(raw); len(m) == 2 {
		electron = string(m[1])
	}
	return chrome, electron, chrome != "" || electron != ""
}

func electronFrameworkInfoPlistPath(binaryPath string) (string, bool) {
	lowerPath := strings.ToLower(binaryPath)
	if !strings.Contains(lowerPath, "electron framework.framework/versions/") {
		return "", false
	}
	if !strings.HasSuffix(lowerPath, "/electron framework") {
		return "", false
	}
	return strings.TrimSuffix(binaryPath, filepath.Base(binaryPath)) + "Resources/Info.plist", true
}

func extractCFBundleVersion(fsys scalibrfs.FS, plistPath string) (string, bool) {
	f, err := fsys.Open(plistPath)
	if err != nil {
		return "", false
	}
	defer f.Close()

	content, err := io.ReadAll(io.LimitReader(f, maxPlistReadBytes))
	if err != nil {
		return "", false
	}

	type plistBundle struct {
		CFBundleVersion string
	}
	var p plistBundle

	r := bytes.NewReader(content)
	header := make([]byte, 8)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", false
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return "", false
	}

	if string(header) == "bplist00" {
		if err := plist.NewBinaryDecoder(r).Decode(&p); err != nil {
			return "", false
		}
	} else {
		if err := plist.NewXMLDecoder(r).Decode(&p); err != nil {
			return "", false
		}
	}
	if p.CFBundleVersion == "" {
		return "", false
	}
	return p.CFBundleVersion, true
}
