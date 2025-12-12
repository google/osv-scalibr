package rust_test

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/reachability/rust"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func Test_Enrich(t *testing.T) {
	e := rust.New()

	tests := []struct {
		name  string
		input *enricher.ScanInput
		inv   *inventory.Inventory
		want  *inventory.Inventory
	}{
		{
			name:  "empty_inventory",
			input: mockInput(t, "testdata/rust-project"),
			inv:   &inventory.Inventory{},
			want:  &inventory.Inventory{},
		},
		{
			name:  "vuln_func_level_data_not_exist",
			input: mockInput(t, "testdata/rust-project"),
			inv: &inventory.Inventory{
				PackageVulns: []*inventory.PackageVuln{
					{
						Vulnerability: &osvschema.Vulnerability{
							Id: "RUSTSEC-2020-0071",
							Affected: []*osvschema.Affected{
								{
									Package: &osvschema.Package{
										Name:      "time",
										Ecosystem: "crates.io",
										Purl:      "pkg:cargo/time",
									},
									EcosystemSpecific: mockEcoSpecData(t, "vuln_func_level_data_not_exist"),
								},
							},
						},
						Package:               &extractor.Package{},
						Plugins:               []string{},
						ExploitabilitySignals: []*vex.FindingExploitabilitySignal{},
					},
				},
			},
			want: &inventory.Inventory{
				PackageVulns: []*inventory.PackageVuln{
					{
						Vulnerability: &osvschema.Vulnerability{
							Id: "RUSTSEC-2020-0071",
							Affected: []*osvschema.Affected{
								{
									Package: &osvschema.Package{
										Name:      "time",
										Ecosystem: "crates.io",
										Purl:      "pkg:cargo/time",
									},
									EcosystemSpecific: mockEcoSpecData(t, "vuln_func_level_data_not_exist"),
								},
							},
						},
						Package:               &extractor.Package{},
						Plugins:               []string{},
						ExploitabilitySignals: []*vex.FindingExploitabilitySignal{},
					},
				},
			},
		},
		{
			name:  "vuln_reachable",
			input: mockInput(t, "testdata/rust-project"),
			inv: &inventory.Inventory{
				PackageVulns: []*inventory.PackageVuln{
					{
						Vulnerability: &osvschema.Vulnerability{
							Id: "RUSTSEC-2020-0071",
							Affected: []*osvschema.Affected{
								{
									Package: &osvschema.Package{
										Name:      "time",
										Ecosystem: "crates.io",
										Purl:      "pkg:cargo/time",
									},
									EcosystemSpecific: mockEcoSpecData(t, "vuln_reachable"),
								},
							},
						},
						Package:               &extractor.Package{},
						Plugins:               []string{},
						ExploitabilitySignals: []*vex.FindingExploitabilitySignal{},
					},
				},
			},
			want: &inventory.Inventory{
				PackageVulns: []*inventory.PackageVuln{
					{
						Vulnerability: &osvschema.Vulnerability{
							Id: "RUSTSEC-2020-0071",
							Affected: []*osvschema.Affected{
								{
									Package: &osvschema.Package{
										Name:      "time",
										Ecosystem: "crates.io",
										Purl:      "pkg:cargo/time",
									},
									EcosystemSpecific: mockEcoSpecData(t, "vuln_reachable"),
								},
							},
						},
						Package:               &extractor.Package{},
						Plugins:               []string{},
						ExploitabilitySignals: []*vex.FindingExploitabilitySignal{},
					},
				},
			},
		},
		{
			name:  "vuln_unreachable",
			input: mockInput(t, "testdata/rust-project"),
			inv: &inventory.Inventory{
				PackageVulns: []*inventory.PackageVuln{
					{
						Vulnerability: &osvschema.Vulnerability{
							Id: "RUSTSEC-2020-0071",
							Affected: []*osvschema.Affected{
								{
									Package: &osvschema.Package{
										Name:      "time",
										Ecosystem: "crates.io",
										Purl:      "pkg:cargo/time",
									},
									EcosystemSpecific: mockEcoSpecData(t, "vuln_unreachable"),
								},
							},
						},
						Package:               &extractor.Package{},
						Plugins:               []string{},
						ExploitabilitySignals: []*vex.FindingExploitabilitySignal{},
					},
				},
			},
			want: &inventory.Inventory{
				PackageVulns: []*inventory.PackageVuln{
					{
						Vulnerability: &osvschema.Vulnerability{
							Id: "RUSTSEC-2020-0071",
							Affected: []*osvschema.Affected{
								{
									Package: &osvschema.Package{
										Name:      "time",
										Ecosystem: "crates.io",
										Purl:      "pkg:cargo/time",
									},
									EcosystemSpecific: mockEcoSpecData(t, "vuln_unreachable"),
								},
							},
						},
						Package: &extractor.Package{},
						Plugins: []string{},
						ExploitabilitySignals: []*vex.FindingExploitabilitySignal{{
							Plugin:        rust.Name,
							Justification: vex.VulnerableCodeNotInExecutePath,
						},
						},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := e.Enrich(t.Context(), tc.input, tc.inv)
			if err != nil {
				t.Errorf("Enrich() returns unexpected error:\n%v", err)
			}
			if diff := cmp.Diff(tc.want, tc.inv, protocmp.Transform()); diff != "" {
				t.Errorf("Enrich() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

// Make ScanInput with target scan root
func mockInput(t *testing.T, root string) *enricher.ScanInput { //nolint:unparam
	t.Helper()
	p, err := filepath.Abs(root)
	if err != nil {
		t.Errorf("cannot create ScanInput from provided scan root path")
	}

	config := enricher.Config{
		ScanRoot: &fs.ScanRoot{
			Path: p,
		},
	}

	return &enricher.ScanInput{
		ScanRoot: config.ScanRoot,
	}
}

func mockEcoSpecData(t *testing.T, tcname string) *structpb.Struct {
	t.Helper()
	baseEcoSpec := map[string]any{
		"affected_functions": nil,
		"affects": map[string]any{
			"functions": []any{}, // Default has no func level vuln data
			"arch":      []any{},
			"os":        []any{},
		},
	}

	switch tc := tcname; tc {
	case "vuln_reachable":
		// Vuln function now_utc is called in test project
		baseEcoSpec["affects"].(map[string]any)["functions"] = []any{"time::OffsetDateTime::now_utc"}
	case "vuln_unreachable":
		baseEcoSpec["affects"].(map[string]any)["functions"] = []any{"time::OffsetDateTime::fake_func"}
	}

	ecoSpecStruct, err := structpb.NewStruct(baseEcoSpec)
	if err != nil {
		t.Fatalf("unexpected error creating mock ecosystem specific data: %v", err)
	}

	return ecoSpecStruct
}
