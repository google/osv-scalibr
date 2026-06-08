package rebarlock_test

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/erlang/rebarlock"
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
			name:      "base rebar.lock",
			inputPath: "rebar.lock",
			want:      true,
		},
		{
			name:      "nested rebar.lock",
			inputPath: filepath.FromSlash("path/to/rebar.lock"),
			want:      true,
		},
		{
			name:      "wrong extension",
			inputPath: filepath.FromSlash("path/to/rebar.lock.script"),
			want:      false,
		},
		{
			name:      "rebar.lock as directory",
			inputPath: filepath.FromSlash("path/to/rebar.lock/file"),
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := rebarlock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("rebarlock.New() error: %v", err)
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
			name: "valid",
			path: "testdata/valid.lock",
			wantPackages: []*extractor.Package{
				{
					Name:     "certifi",
					Version:  "2.14.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPathAndLine("testdata/valid.lock", 2),
				},
				{
					Name:     "cowlib",
					Version:  "2.13.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPathAndLine("testdata/valid.lock", 3),
				},
				{
					Name:     "jsx",
					Version:  "3.1.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPathAndLine("testdata/valid.lock", 4),
				},
				{
					Name:     "clue",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPathAndLine("testdata/valid.lock", 6),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/fogfish/clue",
						Commit: "bd40e3c2a778d4cf85a5cd29b72847b5df9557d1",
					},
				},
			},
		},
		{
			name:         "empty",
			path:         "testdata/empty.lock",
			wantPackages: nil,
		},
		{
			name:         "malformed",
			path:         "testdata/malformed.lock",
			wantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr, err := rebarlock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("rebarlock.New() error: %v", err)
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
