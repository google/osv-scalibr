package vendormodules_test

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/vendormodules"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			name:      "empty",
			inputPath: "",
			want:      false,
		},
		{
			name:      "base modules.txt",
			inputPath: "modules.txt",
			want:      false,
		},
		{
			name:      "vendor modules.txt",
			inputPath: filepath.FromSlash("vendor/modules.txt"),
			want:      true,
		},
		{
			name:      "nested vendor modules.txt",
			inputPath: filepath.FromSlash("path/to/vendor/modules.txt"),
			want:      true,
		},
		{
			name:      "wrong parent",
			inputPath: filepath.FromSlash("path/to/modules.txt"),
			want:      false,
		},
		{
			name:      "modules.txt as directory",
			inputPath: filepath.FromSlash("path/to/vendor/modules.txt/file"),
			want:      false,
		},
		{
			name:      "wrong extension",
			inputPath: filepath.FromSlash("path/to/vendor/modules.txt.bak"),
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := vendormodules.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("vendormodules.New() error: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%q) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantPackages []*extractor.Package
	}{
		{
			name: "with replacements",
			path: "testdata/with-replacements/vendor/modules.txt",
			wantPackages: []*extractor.Package{
				{
					Name:     "github.com/BurntSushi/toml",
					Version:  "1.5.0",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine("testdata/with-replacements/vendor/modules.txt", 1),
				},
				{
					Name:     "golang.org/x/sys",
					Version:  "0.30.0",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine("testdata/with-replacements/vendor/modules.txt", 5),
				},
				{
					Name:     "example.com/new",
					Version:  "1.4.5",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine("testdata/with-replacements/vendor/modules.txt", 8),
				},
				{
					Name:     "example.com/wildcard-fork",
					Version:  "0.2.0",
					PURLType: purl.TypeGolang,
					Location: extractor.LocationFromPathAndLine("testdata/with-replacements/vendor/modules.txt", 11),
				},
			},
		},
		{
			name:         "no packages",
			path:         "testdata/no-packages/vendor/modules.txt",
			wantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr, err := vendormodules.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("vendormodules.New() error: %v", err)
			}

			scanInput := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{Path: tt.path})
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)
			if err != nil {
				t.Fatalf("%s.Extract(%q) error: %v", extr.Name(), tt.path, err)
			}

			wantInv := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.path, diff)
			}
		})
	}
}
