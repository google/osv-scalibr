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

package chromiumapps_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/misc/chromiumapps"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestExtractorFileRequired(t *testing.T) {
	extr, err := chromiumapps.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("chromiumapps.New failed: %v", err)
	}

	tests := []struct {
		path string
		want bool
	}{
		{path: "ProgramFiles/Google/Chrome/Application/137.0.7151.68/chrome.exe", want: true},
		{path: "ProgramFiles/Microsoft/Edge/Application/137.0.3296.62/msedge.exe", want: true},
		{path: "opt/chromium/137.0.7151.68/chrome", want: true},
		{path: "opt/MyApp/resources/electron.asar", want: true},
		{path: "Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework", want: true},
		{path: "opt/MyApp/chrome.dll", want: false},
		{path: "opt/MyApp/random.bin", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := extr.FileRequired(simplefileapi.New(tt.path, nil))
			if got != tt.want {
				t.Fatalf("FileRequired(%q)=%v want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtractorExtract(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		content   string
		plistPath string
		plistData string
		want      []*extractor.Package
		wantErr   error
	}{
		{
			name:    "BinaryChromeVersionPreferred",
			path:    "ProgramFiles/Google/Chrome/Application/1.0.0.0/chrome.exe",
			content: "random bytes Chrome/142.0.7444.265 tail",
			want: []*extractor.Package{{
				Name:      "google-chrome",
				Version:   "142.0.7444.265",
				PURLType:  purl.TypeGeneric,
				Locations: []string{"ProgramFiles/Google/Chrome/Application/1.0.0.0/chrome.exe"},
				Metadata: &chromiumapps.Metadata{
					ChromiumVersion: "142.0.7444.265",
					VersionSource:   "chromium_binary",
				},
			}},
		},
		{
			name:    "ElectronFrameworkBinaryStrings",
			path:    "Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework",
			content: "something Chrome/142.0.7444.265 Electron/39.4.0 end",
			want: []*extractor.Package{{
				Name:      "electron",
				Version:   "142.0.7444.265",
				PURLType:  purl.TypeGeneric,
				Locations: []string{"Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework"},
				Metadata: &chromiumapps.Metadata{
					ChromiumVersion: "142.0.7444.265",
					ElectronVersion: "39.4.0",
					VersionSource:   "chromium_binary",
				},
			}},
		},
		{
			name:    "PathFallbackWhenBinaryMisses",
			path:    "opt/chromium/137.0.7151.67/chrome",
			content: "no chromium token",
			want: []*extractor.Package{{
				Name:      "chromium",
				Version:   "137.0.7151.67",
				PURLType:  purl.TypeGeneric,
				Locations: []string{"opt/chromium/137.0.7151.67/chrome"},
				Metadata: &chromiumapps.Metadata{
					VersionSource: "path",
				},
			}},
		},
		{
			name:      "MacPlistFallbackForElectron",
			path:      "Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework",
			content:   "no version strings",
			plistPath: "Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist",
			plistData: `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleVersion</key><string>39.4.0</string></dict></plist>`,
			want: []*extractor.Package{{
				Name:      "electron",
				Version:   "39.4.0",
				PURLType:  purl.TypeGeneric,
				Locations: []string{"Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework"},
				Metadata: &chromiumapps.Metadata{
					ElectronVersion: "39.4.0",
					VersionSource:   "plist_cf_bundle_version",
				},
			}},
		},
		{
			name:    "UnknownPathSkipped",
			path:    "opt/unknown/137.0.0.0/chrome.exe",
			content: "Chrome/137.0.0.0",
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr, err := chromiumapps.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("chromiumapps.New failed: %v", err)
			}

			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, filepath.Dir(tt.path)), 0o755); err != nil {
				t.Fatalf("MkdirAll(%q): %v", tt.path, err)
			}
			if err := os.WriteFile(filepath.Join(root, tt.path), []byte(tt.content), 0o644); err != nil {
				t.Fatalf("WriteFile(%q): %v", tt.path, err)
			}
			if tt.plistPath != "" {
				if err := os.MkdirAll(filepath.Join(root, filepath.Dir(tt.plistPath)), 0o755); err != nil {
					t.Fatalf("MkdirAll(%q): %v", tt.plistPath, err)
				}
				if err := os.WriteFile(filepath.Join(root, tt.plistPath), []byte(tt.plistData), 0o644); err != nil {
					t.Fatalf("WriteFile(%q): %v", tt.plistPath, err)
				}
			}
			si := scanInputFromRoot(t, root, tt.path)

			got, err := extr.Extract(t.Context(), &si)
			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("Extract() err diff (-want +got):\n%s", diff)
			}

			want := inventory.Inventory{Packages: tt.want}
			if diff := cmp.Diff(want, got, cmpopts.SortSlices(packageCmpLess)); diff != "" {
				t.Fatalf("Extract() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExtractorExtractCancelled(t *testing.T) {
	extr, err := chromiumapps.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("chromiumapps.New failed: %v", err)
	}
	root := t.TempDir()
	path := "ProgramFiles/Google/Chrome/Application/137.0.7151.67/chrome.exe"
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(path)), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, path), []byte("Chrome/137.0.7151.67"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	si := scanInputFromRoot(t, root, path)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = extr.Extract(ctx, &si)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Extract() err=%v want %v", err, context.Canceled)
	}
}

func scanInputFromRoot(t *testing.T, root string, path string) filesystem.ScanInput {
	t.Helper()
	f, err := os.Open(filepath.Join(root, path))
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	t.Cleanup(func() {
		_ = f.Close()
	})
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat(%q): %v", path, err)
	}
	return filesystem.ScanInput{
		FS:     os.DirFS(root).(scalibrfs.FS),
		Path:   filepath.ToSlash(path),
		Root:   root,
		Info:   info,
		Reader: f,
	}
}

func packageCmpLess(a, b *extractor.Package) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	return len(a.Locations) < len(b.Locations)
}
