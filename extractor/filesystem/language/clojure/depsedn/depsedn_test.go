package depsedn_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/clojure/depsedn"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "deps_edn", path: "deps.edn", want: true},
		{name: "nested_deps_edn", path: "path/to/deps.edn", want: true},
		{name: "other_edn", path: "bb.edn", want: false},
		{name: "suffix", path: "deps.edn.bak", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractorPlugin, err := depsedn.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("depsedn.New: %v", err)
			}
			if got := extractorPlugin.FileRequired(simplefileapi.New(tt.path, nil)); got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "deps",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/deps.edn",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "org.clojure:clojure",
					Version:  "1.11.1",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{
						ArtifactID: "clojure",
						GroupID:    "org.clojure",
					},
					Location: extractor.LocationFromPathAndLine("testdata/deps.edn", 3),
				},
				{
					Name:     "com.github.seancorfield:next.jdbc",
					Version:  "1.3.955",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{
						ArtifactID: "next.jdbc",
						GroupID:    "com.github.seancorfield",
					},
					Location: extractor.LocationFromPathAndLine("testdata/deps.edn", 4),
				},
				{
					Name:     "cheshire:cheshire",
					Version:  "5.12.0",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{
						ArtifactID: "cheshire",
						GroupID:    "cheshire",
					},
					Location: extractor.LocationFromPathAndLine("testdata/deps.edn", 13),
				},
			},
		},
		{
			Name: "edge_cases",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/edge-cases.deps.edn",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "org.example:complex",
					Version:  "1.2.3",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{
						ArtifactID: "complex",
						GroupID:    "org.example",
					},
					Location: extractor.LocationFromPathAndLine("testdata/edge-cases.deps.edn", 2),
				},
				{
					Name:     "org.example:duplicate",
					Version:  "1.0.0",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{
						ArtifactID: "duplicate",
						GroupID:    "org.example",
					},
					Location: extractor.LocationFromPathAndLine("testdata/edge-cases.deps.edn", 5),
				},
				{
					Name:     "dev.local:tool",
					Version:  "2.0.0",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{
						ArtifactID: "tool",
						GroupID:    "dev.local",
					},
					Location: extractor.LocationFromPathAndLine("testdata/edge-cases.deps.edn", 10),
				},
				{
					Name:     "org.example:replaced",
					Version:  "3.0.0",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{
						ArtifactID: "replaced",
						GroupID:    "org.example",
					},
					Location: extractor.LocationFromPathAndLine("testdata/edge-cases.deps.edn", 13),
				},
				{
					Name:     "org.replace:core",
					Version:  "4.0.0",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{
						ArtifactID: "core",
						GroupID:    "org.replace",
					},
					Location: extractor.LocationFromPathAndLine("testdata/edge-cases.deps.edn", 15),
				},
				{
					Name:     "default.lib:core",
					Version:  "5.0.0",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{
						ArtifactID: "core",
						GroupID:    "default.lib",
					},
					Location: extractor.LocationFromPathAndLine("testdata/edge-cases.deps.edn", 17),
				},
				{
					Name:     "override.lib:core",
					Version:  "6.0.0",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{
						ArtifactID: "core",
						GroupID:    "override.lib",
					},
					Location: extractor.LocationFromPathAndLine("testdata/edge-cases.deps.edn", 18),
				},
			},
		},
		{
			Name: "malformed_deps",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/malformed-deps.edn",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "no_maven_dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-maven-deps.edn",
			},
			WantPackages: []*extractor.Package{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := depsedn.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("depsedn.New: %v", err)
			}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)
			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
