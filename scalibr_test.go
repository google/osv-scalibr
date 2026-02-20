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

package scalibr_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/annotator/cachedir"
	"github.com/google/osv-scalibr/artifact/image"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/fakeimage"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/fakelayerbuilder"
	"github.com/google/osv-scalibr/enricher"
	ce "github.com/google/osv-scalibr/enricher/secrets/convert"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	cf "github.com/google/osv-scalibr/extractor/filesystem/secrets/convert"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
	fd "github.com/google/osv-scalibr/testing/fakedetector"
	fen "github.com/google/osv-scalibr/testing/fakeenricher"
	fe "github.com/google/osv-scalibr/testing/fakeextractor"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/velestest"
	"github.com/google/osv-scalibr/version"
	"github.com/mohae/deepcopy"
	"github.com/opencontainers/go-digest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func fromVelesDetector(t *testing.T, d veles.Detector, name string, ver int) plugin.Plugin {
	t.Helper()
	p, err := cf.FromVelesDetector(d, name, ver)(nil)
	if err != nil {
		t.Fatalf("Failed to create plugin from Veles detector: %v", err)
	}
	return p
}

func TestScan(t *testing.T) {
	success := &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}
	partialSuccess := &plugin.ScanStatus{
		Status:        plugin.ScanStatusPartiallySucceeded,
		FailureReason: "not all plugins succeeded, see the plugin statuses",
	}
	pluginFailure := "failed to run plugin"
	extFailure := &plugin.ScanStatus{
		Status:        plugin.ScanStatusFailed,
		FailureReason: "encountered 1 error(s) while running plugin; check file-specific errors for details",
		FileErrors: []*plugin.FileError{
			{FilePath: "file.txt", ErrorMessage: pluginFailure},
		},
	}
	detFailure := &plugin.ScanStatus{
		Status:        plugin.ScanStatusFailed,
		FailureReason: pluginFailure,
	}
	enrFailure := &plugin.ScanStatus{
		Status:        plugin.ScanStatusFailed,
		FailureReason: "API: " + pluginFailure,
	}

	tmp := t.TempDir()
	fs := scalibrfs.DirFS(tmp)
	tmpRoot := []*scalibrfs.ScanRoot{{FS: fs, Path: tmp}}
	_ = os.WriteFile(filepath.Join(tmp, "file.txt"), []byte("Content"), 0644)
	_ = os.WriteFile(filepath.Join(tmp, "config"), []byte("Content"), 0644)

	pkgName := "software"
	fakeExtractor := fe.New(
		"python/wheelegg", 1, []string{"file.txt"},
		map[string]fe.NamesErr{"file.txt": {Names: []string{pkgName}, Err: nil}},
	)
	pkg := &extractor.Package{
		Name:      pkgName,
		Locations: []string{"file.txt"},
		ScanRoot:  tmp,
		Plugins:   []string{fakeExtractor.Name()},
	}
	pkgWithAbsolutePath := &extractor.Package{
		Name:      pkgName,
		Locations: []string{filepath.Join(tmp, "file.txt")},
		ScanRoot:  tmp,
		Plugins:   []string{fakeExtractor.Name()},
	}
	withLayerMetadata := func(pkg *extractor.Package, ld *extractor.LayerMetadata) *extractor.Package {
		pkg = deepcopy.Copy(pkg).(*extractor.Package)
		pkg.LayerMetadata = ld
		return pkg
	}
	pkgWithLayerMetadata := withLayerMetadata(pkg, &extractor.LayerMetadata{Index: 0, DiffID: "diff-id-0", Command: "command-0"})
	pkgWithLayerMetadata.Plugins = []string{fakeExtractor.Name()}
	finding := &inventory.GenericFinding{Adv: &inventory.GenericFindingAdvisory{ID: &inventory.AdvisoryID{Reference: "CVE-1234"}}}

	fakeEnricherCfg := &fen.Config{
		Name:         "enricher",
		Version:      1,
		Capabilities: &plugin.Capabilities{Network: plugin.NetworkOnline},
		WantEnrich: map[uint64]fen.InventoryAndErr{
			fen.MustHash(
				t,
				&enricher.ScanInput{
					ScanRoot: &scalibrfs.ScanRoot{
						FS:   fs,
						Path: tmp,
					},
				},
				&inventory.Inventory{
					Packages: []*extractor.Package{pkg},
					GenericFindings: []*inventory.GenericFinding{
						withDetectorName(finding, "detector"),
					},
				},
			): {
				Inventory: &inventory.Inventory{
					Packages: []*extractor.Package{pkgWithLayerMetadata},
					GenericFindings: []*inventory.GenericFinding{
						withDetectorName(finding, "detector"),
					},
				},
			},
		},
	}
	fakeEnricher := fen.MustNew(t, fakeEnricherCfg)

	fakeEnricherCfgErr := &fen.Config{
		Name:         "enricher",
		Version:      1,
		Capabilities: &plugin.Capabilities{Network: plugin.NetworkOnline},
		WantEnrich: map[uint64]fen.InventoryAndErr{
			fen.MustHash(
				t, &enricher.ScanInput{ScanRoot: &scalibrfs.ScanRoot{FS: fs, Path: tmp}},
				&inventory.Inventory{
					Packages: []*extractor.Package{pkg},
					GenericFindings: []*inventory.GenericFinding{
						withDetectorName(finding, "detector2"),
					},
				},
			): {
				Inventory: &inventory.Inventory{
					Packages: []*extractor.Package{pkg},
					GenericFindings: []*inventory.GenericFinding{
						withDetectorName(finding, "detector2"),
					},
				},
				Err: errors.New(enrFailure.FailureReason),
			},
		},
	}
	fakeEnricherErr := fen.MustNew(t, fakeEnricherCfgErr)

	fakeSecretDetector1 := velestest.NewFakeDetector("Con")
	fakeSecretDetector2 := velestest.NewFakeDetector("tent")
	fakeSecretValidator1 := velestest.NewFakeStringSecretValidator(veles.ValidationValid, nil)

	testCases := []struct {
		desc string
		cfg  *scalibr.ScanConfig
		want *scalibr.ScanResult
	}{
		{
			desc: "Successful_scan",
			cfg: &scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fakeExtractor,
					fd.New().WithName("detector").WithVersion(2).WithGenericFinding(finding),
					fakeEnricher,
				},
				ScanRoots: tmpRoot,
			},
			want: &scalibr.ScanResult{
				Version: version.ScannerVersion,
				Status:  success,
				PluginStatus: []*plugin.Status{
					{Name: "detector", Version: 2, Status: success},
					{Name: "enricher", Version: 1, Status: success},
					{Name: "python/wheelegg", Version: 1, Status: success},
				},
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{pkgWithLayerMetadata},
					GenericFindings: []*inventory.GenericFinding{
						withDetectorName(finding, "detector"),
					},
				},
			},
		},
		{
			desc: "Global_error",
			cfg: &scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					// Will error due to duplicate non-identical Advisories.
					fd.New().WithName("detector").WithVersion(2).WithGenericFinding(finding),
					fd.New().WithName("detector").WithVersion(3).WithGenericFinding(&inventory.GenericFinding{
						Adv: &inventory.GenericFindingAdvisory{ID: finding.Adv.ID, Title: "different title"},
					}),
				},
				ScanRoots: tmpRoot,
			},
			want: &scalibr.ScanResult{
				Version: version.ScannerVersion,
				Status: &plugin.ScanStatus{
					Status:        plugin.ScanStatusFailed,
					FailureReason: "multiple non-identical advisories with ID &{ CVE-1234}",
				},
				PluginStatus: []*plugin.Status{
					{Name: "detector", Version: 2, Status: success},
					{Name: "detector", Version: 3, Status: success},
				},
			},
		},
		{
			desc: "Extractor_plugin_failed",
			cfg: &scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fe.New("python/wheelegg", 1, []string{"file.txt"}, map[string]fe.NamesErr{"file.txt": {Names: nil, Err: errors.New(pluginFailure)}}),
					fd.New().WithName("detector").WithVersion(2).WithGenericFinding(finding),
				},
				ScanRoots: tmpRoot,
			},
			want: &scalibr.ScanResult{
				Version: version.ScannerVersion,
				Status:  partialSuccess,
				PluginStatus: []*plugin.Status{
					{Name: "detector", Version: 2, Status: success},
					{Name: "python/wheelegg", Version: 1, Status: extFailure},
				},
				Inventory: inventory.Inventory{
					Packages: nil,
					GenericFindings: []*inventory.GenericFinding{
						withDetectorName(finding, "detector"),
					},
				},
			},
		},
		{
			desc: "Detector_plugin_failed",
			cfg: &scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fakeExtractor,
					fd.New().WithName("detector").WithVersion(2).WithErr(errors.New(pluginFailure)),
				},
				ScanRoots: tmpRoot,
			},
			want: &scalibr.ScanResult{
				Version: version.ScannerVersion,
				Status:  partialSuccess,
				PluginStatus: []*plugin.Status{
					{Name: "detector", Version: 2, Status: detFailure},
					{Name: "python/wheelegg", Version: 1, Status: success},
				},
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{pkg},
				},
			},
		},
		{
			desc: "Enricher_plugin_failed",
			cfg: &scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fakeExtractor,
					fd.New().WithName("detector2").WithVersion(2).WithGenericFinding(finding),
					fakeEnricherErr,
				},
				ScanRoots: tmpRoot,
			},
			want: &scalibr.ScanResult{
				Version: version.ScannerVersion,
				Status:  partialSuccess,
				PluginStatus: []*plugin.Status{
					{Name: "detector2", Version: 2, Status: success},
					{Name: "enricher", Version: 1, Status: enrFailure},
					{Name: "python/wheelegg", Version: 1, Status: success},
				},
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{pkg},
					GenericFindings: []*inventory.GenericFinding{
						withDetectorName(finding, "detector2"),
					},
				},
			},
		},
		{
			desc: "Missing_scan_roots_causes_error",
			cfg: &scalibr.ScanConfig{
				Plugins:   []plugin.Plugin{fakeExtractor},
				ScanRoots: []*scalibrfs.ScanRoot{},
			},
			want: &scalibr.ScanResult{
				Version: version.ScannerVersion,
				Status: &plugin.ScanStatus{
					Status:        plugin.ScanStatusFailed,
					FailureReason: "no scan root specified",
				},
			},
		},
		{
			desc: "Store_absolute_paths",
			cfg: &scalibr.ScanConfig{
				Plugins:           []plugin.Plugin{fakeExtractor},
				ScanRoots:         tmpRoot,
				StoreAbsolutePath: true,
			},
			want: &scalibr.ScanResult{
				Version: version.ScannerVersion,
				Status:  success,
				PluginStatus: []*plugin.Status{
					{Name: "python/wheelegg", Version: 1, Status: success},
				},
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{pkgWithAbsolutePath},
				},
			},
		},
		{
			desc: "One_Veles_secret_detector",
			cfg: &scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fromVelesDetector(t, fakeSecretDetector1, "secret-detector", 1),
				},
				ScanRoots: tmpRoot,
			},
			want: &scalibr.ScanResult{
				Version: version.ScannerVersion,
				Status:  success,
				PluginStatus: []*plugin.Status{
					{Name: "secrets/veles", Version: 1, Status: success},
				},
				Inventory: inventory.Inventory{
					Secrets: []*inventory.Secret{{Secret: velestest.NewFakeStringSecret("Con"), Location: "file.txt"}},
				},
			},
		},
		{
			desc: "Two_Veles_secret_detectors",
			cfg: &scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fromVelesDetector(t, fakeSecretDetector1, "secret-detector-1", 1),
					fromVelesDetector(t, fakeSecretDetector2, "secret-detector-2", 2),
				},
				ScanRoots: tmpRoot,
			},
			want: &scalibr.ScanResult{
				Version: version.ScannerVersion,
				Status:  success,
				PluginStatus: []*plugin.Status{
					{Name: "secrets/veles", Version: 1, Status: success},
				},
				Inventory: inventory.Inventory{
					Secrets: []*inventory.Secret{
						{Secret: velestest.NewFakeStringSecret("Con"), Location: "file.txt"},
						{Secret: velestest.NewFakeStringSecret("tent"), Location: "file.txt"},
					},
				},
			},
		},
		{
			desc: "Veles_secret_detector_with_validation",
			cfg: &scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fromVelesDetector(t, fakeSecretDetector1, "secret-detector", 1),
					ce.FromVelesValidator(fakeSecretValidator1, "secret-validator", 1)(),
				},
				ScanRoots: tmpRoot,
			},
			want: &scalibr.ScanResult{
				Version: version.ScannerVersion,
				Status:  success,
				PluginStatus: []*plugin.Status{
					{Name: "secrets/veles", Version: 1, Status: success},
					{Name: "secrets/velesvalidate", Version: 1, Status: success},
				},
				Inventory: inventory.Inventory{
					Secrets: []*inventory.Secret{{
						Secret:     velestest.NewFakeStringSecret("Con"),
						Location:   "file.txt",
						Validation: inventory.SecretValidationResult{Status: veles.ValidationValid},
					}},
				},
			},
		},
		{
			desc: "Veles_secret_detector_with_extractor",
			cfg: &scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					// use the fakeSecretDetector1 also on config files
					cf.FromVelesDetectorWithRequire(
						fakeSecretDetector1, "secret-detector", 1,
						func(fa filesystem.FileAPI) bool {
							return strings.HasSuffix(fa.Path(), "config")
						},
					),
				},
				ScanRoots: tmpRoot,
			},
			want: &scalibr.ScanResult{
				Version: version.ScannerVersion,
				Status:  success,
				PluginStatus: []*plugin.Status{
					{Name: "secret-detector", Version: 1, Status: success},
					{Name: "secrets/veles", Version: 1, Status: success},
				},
				Inventory: inventory.Inventory{
					Secrets: []*inventory.Secret{
						{Secret: velestest.NewFakeStringSecret("Con"), Location: "file.txt"},
						{Secret: velestest.NewFakeStringSecret("Con"), Location: "config"},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := scalibr.New().Scan(t.Context(), tc.cfg)

			// We can't mock the time from here so we skip it in the comparison.
			tc.want.StartTime = got.StartTime
			tc.want.EndTime = got.EndTime

			// Ignore timestamps.
			ignoreFields := cmpopts.IgnoreFields(inventory.SecretValidationResult{}, "At")

			ignoreOrder := cmpopts.SortSlices(func(a, b any) bool {
				return fmt.Sprintf("%+v", a) < fmt.Sprintf("%+v", b)
			})

			if diff := cmp.Diff(tc.want, got, fe.AllowUnexported, ignoreFields, ignoreOrder); diff != "" {
				t.Errorf("scalibr.New().Scan(%v): unexpected diff (-want +got):\n%s", tc.cfg, diff)
			}
		})
	}
}

func TestScanContainer(t *testing.T) {
	fakeChainLayers := fakelayerbuilder.BuildFakeChainLayersFromPath(t, t.TempDir(),
		"testdata/populatelayers.yml")

	lm := func(i int) *extractor.LayerMetadata {
		return &extractor.LayerMetadata{
			Index:   i,
			DiffID:  digest.Digest(fmt.Sprintf("sha256:diff-id-%d", i)),
			ChainID: digest.Digest(fmt.Sprintf("sha256:chain-id-%d", i)),
			Command: fmt.Sprintf("command-%d", i),
		}
	}

	testCases := []struct {
		desc        string
		chainLayers []image.ChainLayer
		want        *scalibr.ScanResult
		wantErr     error
	}{
		{
			desc: "Successful_scan_with_1_layer,_2_packages",
			chainLayers: []image.ChainLayer{
				fakeChainLayers[0],
			},
			want: &scalibr.ScanResult{
				Version: version.ScannerVersion,
				Status:  &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
				PluginStatus: []*plugin.Status{
					{
						Name:    "fake/layerextractor",
						Version: 0,
						Status:  &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
					},
				},
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{
						{
							Name:          "bar",
							Locations:     []string{"bar.txt"},
							PURLType:      "generic",
							Plugins:       []string{"fake/layerextractor"},
							LayerMetadata: lm(0),
						},
						{
							Name:          "foo",
							Locations:     []string{"foo.txt"},
							PURLType:      "generic",
							Plugins:       []string{"fake/layerextractor"},
							LayerMetadata: lm(0),
						},
					},
					ContainerImageMetadata: []*extractor.ContainerImageMetadata{
						{
							LayerMetadata: []*extractor.LayerMetadata{lm(0)},
						},
					},
				},
			},
		},
		{
			desc: "Successful_scan_with_2_layers,_1_package_deleted_in_last_layer",
			chainLayers: []image.ChainLayer{
				fakeChainLayers[0],
				fakeChainLayers[1],
			},
			want: &scalibr.ScanResult{
				Version: version.ScannerVersion,
				Status:  &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
				PluginStatus: []*plugin.Status{
					{
						Name:    "fake/layerextractor",
						Version: 0,
						Status:  &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
					},
				},
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{
						{
							Name:          "foo",
							Locations:     []string{"foo.txt"},
							PURLType:      "generic",
							Plugins:       []string{"fake/layerextractor"},
							LayerMetadata: lm(0),
						},
					},
					ContainerImageMetadata: []*extractor.ContainerImageMetadata{
						{
							LayerMetadata: []*extractor.LayerMetadata{lm(0), lm(1)},
						},
					},
				},
			},
		},
		{
			desc: "Successful_scan_with_3_layers,_package_readded_in_last_layer",
			chainLayers: []image.ChainLayer{
				fakeChainLayers[0],
				fakeChainLayers[1],
				fakeChainLayers[2],
			},
			want: &scalibr.ScanResult{
				Version: version.ScannerVersion,
				Status:  &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
				PluginStatus: []*plugin.Status{
					{
						Name:    "fake/layerextractor",
						Version: 0,
						Status:  &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
					},
				},
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{
						{
							Name:          "baz",
							Locations:     []string{"baz.txt"},
							PURLType:      "generic",
							Plugins:       []string{"fake/layerextractor"},
							LayerMetadata: lm(2),
						},
						{
							Name:          "foo",
							Locations:     []string{"foo.txt"},
							PURLType:      "generic",
							Plugins:       []string{"fake/layerextractor"},
							LayerMetadata: lm(0),
						},
					},
					ContainerImageMetadata: []*extractor.ContainerImageMetadata{
						{
							LayerMetadata: []*extractor.LayerMetadata{lm(0), lm(1), lm(2)},
						},
					},
				},
			},
		},
		{
			desc: "Successful_scan_with_4_layers",
			chainLayers: []image.ChainLayer{
				fakeChainLayers[0],
				fakeChainLayers[1],
				fakeChainLayers[2],
				fakeChainLayers[3],
			},
			want: &scalibr.ScanResult{
				Version: version.ScannerVersion,
				Status:  &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
				PluginStatus: []*plugin.Status{
					{
						Name:    "fake/layerextractor",
						Version: 0,
						Status:  &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
					},
				},
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{
						{
							Name:          "bar",
							Locations:     []string{"bar.txt"},
							PURLType:      "generic",
							Plugins:       []string{"fake/layerextractor"},
							LayerMetadata: lm(3),
						},
						{
							Name:          "baz",
							Locations:     []string{"baz.txt"},
							PURLType:      "generic",
							Plugins:       []string{"fake/layerextractor"},
							LayerMetadata: lm(2),
						},
						{
							Name:          "foo",
							Locations:     []string{"foo.txt"},
							PURLType:      "generic",
							Plugins:       []string{"fake/layerextractor"},
							LayerMetadata: lm(0),
						},
					},
					ContainerImageMetadata: []*extractor.ContainerImageMetadata{
						{
							LayerMetadata: []*extractor.LayerMetadata{lm(0), lm(1), lm(2), lm(3)},
						},
					},
				},
			},
		},
		{
			desc: "Successful_scan_with_5_layers",
			chainLayers: []image.ChainLayer{
				fakeChainLayers[0],
				fakeChainLayers[1],
				fakeChainLayers[2],
				fakeChainLayers[3],
				fakeChainLayers[4],
			},
			want: &scalibr.ScanResult{
				Version: version.ScannerVersion,
				Status:  &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
				PluginStatus: []*plugin.Status{
					{
						Name:    "fake/layerextractor",
						Version: 0,
						Status:  &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
					},
				},
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{
						{
							Name:          "bar",
							Locations:     []string{"bar.txt"},
							PURLType:      "generic",
							Plugins:       []string{"fake/layerextractor"},
							LayerMetadata: lm(3),
						},
						{
							Name:          "baz",
							Locations:     []string{"baz.txt"},
							PURLType:      "generic",
							Plugins:       []string{"fake/layerextractor"},
							LayerMetadata: lm(2),
						},
						{
							Name:          "foo",
							Locations:     []string{"foo.txt"},
							PURLType:      "generic",
							Plugins:       []string{"fake/layerextractor"},
							LayerMetadata: lm(0),
						},
						{
							Name:          "foo2",
							Locations:     []string{"foo.txt"},
							PURLType:      "generic",
							Plugins:       []string{"fake/layerextractor"},
							LayerMetadata: lm(4),
						},
					},
					ContainerImageMetadata: []*extractor.ContainerImageMetadata{
						{
							LayerMetadata: []*extractor.LayerMetadata{lm(0), lm(1), lm(2), lm(3), lm(4)},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			scanConfig := scalibr.ScanConfig{Plugins: []plugin.Plugin{
				fakelayerbuilder.FakeTestLayersExtractor{},
			}}

			fi := fakeimage.New(tc.chainLayers)
			got, err := scalibr.New().ScanContainer(t.Context(), fi, &scanConfig)

			if tc.wantErr != nil {
				if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
					t.Errorf("scalibr.New().ScanContainer(): unexpected error diff (-want +got):\n%s", diff)
				}
			}
			// We can't mock the time from here so we skip it in the comparison.
			tc.want.StartTime = got.StartTime
			tc.want.EndTime = got.EndTime

			if diff := cmp.Diff(tc.want, got, fe.AllowUnexported, cmpopts.IgnoreFields(extractor.LayerMetadata{}, "ParentContainer")); diff != "" {
				t.Errorf("scalibr.New().Scan(): unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestScan_ExtractorOverride(t *testing.T) {
	tmp := t.TempDir()
	fs := scalibrfs.DirFS(tmp)
	if err := os.WriteFile(filepath.Join(tmp, "file1"), []byte("content1"), 0644); err != nil {
		t.Fatalf("write file1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "file2"), []byte("content2"), 0644); err != nil {
		t.Fatalf("write file2: %v", err)
	}
	if err := os.Mkdir(filepath.Join(tmp, "dir"), 0755); err != nil {
		t.Fatalf("mkdir dir: %v", err)
	}
	tmpRoot := []*scalibrfs.ScanRoot{{FS: fs, Path: tmp}}

	e1 := fe.New("e1", 1, []string{"file1"}, map[string]fe.NamesErr{"file1": {Names: []string{"pkg1"}}})
	e2 := fe.New("e2", 1, []string{"file2"}, map[string]fe.NamesErr{"file2": {Names: []string{"pkg2"}}})
	e3 := fe.New("e3", 1, []string{}, map[string]fe.NamesErr{"file2": {Names: []string{"pkg3"}}})
	e4 := fe.NewDirExtractor("e4", 1, []string{"dir"}, map[string]fe.NamesErr{"dir": {Names: []string{"pkg4"}}})
	e5 := fe.NewDirExtractor("e5", 1, []string{"notdir"}, map[string]fe.NamesErr{"dir": {Names: []string{"pkg5"}}})

	pkg1 := &extractor.Package{Name: "pkg1", Locations: []string{"file1"}, ScanRoot: tmp, Plugins: []string{"e1"}}
	pkg2 := &extractor.Package{Name: "pkg2", Locations: []string{"file2"}, ScanRoot: tmp, Plugins: []string{"e2"}}
	pkg3 := &extractor.Package{Name: "pkg3", Locations: []string{"file2"}, ScanRoot: tmp, Plugins: []string{"e3"}}
	pkg4 := &extractor.Package{Name: "pkg4", Locations: []string{"dir"}, ScanRoot: tmp, Plugins: []string{"e4"}}
	pkg5 := &extractor.Package{Name: "pkg5", Locations: []string{"dir"}, ScanRoot: tmp, Plugins: []string{"e5"}}

	tests := []struct {
		name              string
		plugins           []plugin.Plugin
		extractorOverride func(filesystem.FileAPI) []filesystem.Extractor
		wantPkgs          []*extractor.Package
	}{
		{
			name:    "no override",
			plugins: []plugin.Plugin{e1, e2, e3},
			wantPkgs: []*extractor.Package{
				pkg1, pkg2,
			},
		},
		{
			name:    "override returns nil",
			plugins: []plugin.Plugin{e1, e2, e3},
			extractorOverride: func(api filesystem.FileAPI) []filesystem.Extractor {
				return nil
			},
			wantPkgs: []*extractor.Package{
				pkg1, pkg2,
			},
		},
		{
			name:    "override returns empty",
			plugins: []plugin.Plugin{e1, e2, e3},
			extractorOverride: func(api filesystem.FileAPI) []filesystem.Extractor {
				return []filesystem.Extractor{}
			},
			wantPkgs: []*extractor.Package{
				pkg1, pkg2,
			},
		},
		{
			name:    "override e3 for file2",
			plugins: []plugin.Plugin{e1, e2, e3},
			extractorOverride: func(api filesystem.FileAPI) []filesystem.Extractor {
				if api.Path() == "file2" {
					return []filesystem.Extractor{e3}
				}
				return nil
			},
			wantPkgs: []*extractor.Package{
				pkg1, pkg3,
			},
		},
		{
			name:    "override e5 for irrelevant directory",
			plugins: []plugin.Plugin{e1, e4, e5},
			extractorOverride: func(api filesystem.FileAPI) []filesystem.Extractor {
				if api.Path() == "otherdir" {
					return []filesystem.Extractor{e5}
				}
				return nil
			},
			wantPkgs: []*extractor.Package{
				pkg1, pkg4,
			},
		},
		{
			name:    "override e5 for dir",
			plugins: []plugin.Plugin{e1, e4, e5},
			extractorOverride: func(api filesystem.FileAPI) []filesystem.Extractor {
				if api.Path() == "dir" {
					return []filesystem.Extractor{e5}
				}
				return nil
			},
			wantPkgs: []*extractor.Package{
				pkg1, pkg5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &scalibr.ScanConfig{
				Plugins:           tt.plugins,
				ScanRoots:         tmpRoot,
				ExtractorOverride: tt.extractorOverride,
			}
			res := scalibr.New().Scan(t.Context(), cfg)
			if res.Status.Status != plugin.ScanStatusSucceeded {
				t.Fatalf("Scan failed: %s", res.Status.FailureReason)
			}

			sortSlices := cmpopts.SortSlices(func(a, b *extractor.Package) bool { return scalibr.CmpPackages(a, b) < 0 })
			if diff := cmp.Diff(tt.wantPkgs, res.Inventory.Packages, fe.AllowUnexported, sortSlices, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Scan() packages diff (-want +got):\n%s", diff)
			}
		})
	}
}

func withDetectorName(f *inventory.GenericFinding, det string) *inventory.GenericFinding {
	c := *f
	c.Plugins = []string{det}
	return &c
}

func TestEnableRequiredPlugins(t *testing.T) {
	cases := []struct {
		name        string
		cfg         scalibr.ScanConfig
		wantPlugins []string
		wantErr     error
	}{
		{
			name: "empty",
		},
		{
			name: "no_required_extractors",
			cfg: scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fd.New().WithName("foo"),
				},
			},
			wantPlugins: []string{"foo"},
		},
		{
			name: "required_extractor_in_already_enabled",
			cfg: scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fd.New().WithName("foo").WithRequiredExtractors("bar/baz"),
					fe.New("bar/baz", 0, nil, nil),
				},
			},
			wantPlugins: []string{"foo", "bar/baz"},
		},
		{
			name: "auto-loaded_required_extractor",
			cfg: scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fd.New().WithName("foo").WithRequiredExtractors("python/wheelegg"),
				},
			},
			wantPlugins: []string{"foo", "python/wheelegg"},
		},
		{
			name: "auto-loaded_required_extractor_by_enricher",
			cfg: scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fen.MustNew(t, &fen.Config{Name: "foo", RequiredPlugins: []string{"python/wheelegg"}}),
				},
			},
			wantPlugins: []string{"foo", "python/wheelegg"},
		},
		{
			name: "required_extractor_doesn't_exist",
			cfg: scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fd.New().WithName("foo").WithRequiredExtractors("bar/baz"),
				},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			name: "explicit_plugins_enabled",
			cfg: scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fd.New().WithName("foo").WithRequiredExtractors("python/wheelegg"),
				},
				ExplicitPlugins: true,
			},
			wantErr: cmpopts.AnyError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.EnableRequiredPlugins(); !cmp.Equal(tc.wantErr, err, cmpopts.EquateErrors()) {
				t.Fatalf("EnableRequiredPlugins() error: %v, want %v", tc.wantErr, err)
			}
			if tc.wantErr == nil {
				gotPlugins := []string{}
				for _, p := range tc.cfg.Plugins {
					gotPlugins = append(gotPlugins, p.Name())
				}
				if diff := cmp.Diff(
					tc.wantPlugins,
					gotPlugins,
					cmpopts.EquateEmpty(),
					cmpopts.SortSlices(func(l, r string) bool { return l < r }),
				); diff != "" {
					t.Errorf("EnableRequiredPlugins() diff (-want, +got):\n%s", diff)
				}
			}
		})
	}
}

type fakeExNeedsNetwork struct{}

func (fakeExNeedsNetwork) Name() string                           { return "fake-extractor" }
func (fakeExNeedsNetwork) Version() int                           { return 0 }
func (fakeExNeedsNetwork) FileRequired(_ filesystem.FileAPI) bool { return false }
func (fakeExNeedsNetwork) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	return inventory.Inventory{}, nil
}
func (fakeExNeedsNetwork) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{Network: plugin.NetworkOnline}
}

type fakeDetNeedsFS struct {
}

func (fakeDetNeedsFS) Name() string                       { return "fake-extractor" }
func (fakeDetNeedsFS) Version() int                       { return 0 }
func (fakeDetNeedsFS) RequiredExtractors() []string       { return nil }
func (fakeDetNeedsFS) DetectedFinding() inventory.Finding { return inventory.Finding{} }
func (fakeDetNeedsFS) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	return inventory.Finding{}, nil
}
func (fakeDetNeedsFS) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{DirectFS: true}
}

func TestValidatePluginRequirements(t *testing.T) {
	cases := []struct {
		desc    string
		cfg     scalibr.ScanConfig
		wantErr error
	}{
		{
			desc: "requirements_satisfied",
			cfg: scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					&fakeExNeedsNetwork{},
					&fakeDetNeedsFS{},
					fen.MustNew(t, &fen.Config{
						Name:    "enricher",
						Version: 1,
						Capabilities: &plugin.Capabilities{
							Network:  plugin.NetworkOnline,
							DirectFS: true,
						},
					}),
				},
				Capabilities: &plugin.Capabilities{
					Network:  plugin.NetworkOnline,
					DirectFS: true,
				},
			},
			wantErr: nil,
		},
		{
			desc: "one_detector's_requirements_unsatisfied",
			cfg: scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					&fakeExNeedsNetwork{},
					&fakeDetNeedsFS{},
				},
				Capabilities: &plugin.Capabilities{
					Network:  plugin.NetworkOffline,
					DirectFS: true,
				},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "one_enrichers's_requirements_unsatisfied",
			cfg: scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					&fakeExNeedsNetwork{},
					fen.MustNew(t, &fen.Config{
						Name:    "enricher",
						Version: 1,
						Capabilities: &plugin.Capabilities{
							Network:  plugin.NetworkOnline,
							DirectFS: true,
						},
					}),
				},
				Capabilities: &plugin.Capabilities{
					Network:  plugin.NetworkOffline,
					DirectFS: true,
				},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "both_plugin's_requirements_unsatisfied",
			cfg: scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					&fakeExNeedsNetwork{},
					&fakeDetNeedsFS{},
				},
				Capabilities: &plugin.Capabilities{
					Network:  plugin.NetworkOffline,
					DirectFS: false,
				},
			},
			wantErr: cmpopts.AnyError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if err := tc.cfg.ValidatePluginRequirements(); !cmp.Equal(tc.wantErr, err, cmpopts.EquateErrors()) {
				t.Fatalf("ValidatePluginRequirements() error: %v, want %v", tc.wantErr, err)
			}
		})
	}
}

type errorFS struct {
	err error
}

func (f errorFS) Open(name string) (fs.File, error)          { return nil, f.err }
func (f errorFS) ReadDir(name string) ([]fs.DirEntry, error) { return nil, f.err }
func (f errorFS) Stat(name string) (fs.FileInfo, error)      { return nil, f.err }

func TestErrorOnFSErrors(t *testing.T) {
	cases := []struct {
		desc            string
		ErrorOnFSErrors bool
		wantstatus      plugin.ScanStatusEnum
	}{
		{
			desc:            "ErrorOnFSErrors_is_false",
			ErrorOnFSErrors: false,
			wantstatus:      plugin.ScanStatusSucceeded,
		},
		{
			desc:            "ErrorOnFSErrors_is_true",
			ErrorOnFSErrors: true,
			wantstatus:      plugin.ScanStatusFailed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			fs := errorFS{err: errors.New("some error")}
			cfg := &scalibr.ScanConfig{
				ScanRoots: []*scalibrfs.ScanRoot{{FS: fs}},
				Plugins: []plugin.Plugin{
					// Just a random extractor, such that walk is running.
					fe.New("python/wheelegg", 1, []string{"file.txt"}, map[string]fe.NamesErr{"file.txt": {Names: []string{"software"}}}),
				},
				ErrorOnFSErrors: tc.ErrorOnFSErrors,
			}

			got := scalibr.New().Scan(t.Context(), cfg)

			if got.Status.Status != tc.wantstatus {
				t.Errorf("Scan() status: %v, want %v", got.Status.Status, tc.wantstatus)
			}
		})
	}
}

func TestAnnotator(t *testing.T) {
	tmp := t.TempDir()
	tmpRoot := []*scalibrfs.ScanRoot{{FS: scalibrfs.DirFS(tmp), Path: tmp}}
	log.Warn(filepath.Join(tmp, "file.txt"))

	cacheDir := filepath.Join(tmp, "tmp")
	_ = os.Mkdir(cacheDir, fs.ModePerm)
	_ = os.WriteFile(filepath.Join(cacheDir, "file.txt"), []byte("Content"), 0644)

	pkgName := "cached"
	fakeExtractor := fe.New(
		"python/wheelegg", 1, []string{"tmp/file.txt"},
		map[string]fe.NamesErr{"tmp/file.txt": {Names: []string{pkgName}, Err: nil}},
	)

	anno, err := cachedir.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &scalibr.ScanConfig{
		Plugins:   []plugin.Plugin{fakeExtractor, anno},
		ScanRoots: tmpRoot,
	}

	wantPkgs := []*extractor.Package{{
		Name:      pkgName,
		Locations: []string{"tmp/file.txt"},
		ScanRoot:  tmp,
		Plugins:   []string{fakeExtractor.Name()},
		ExploitabilitySignals: []*vex.PackageExploitabilitySignal{&vex.PackageExploitabilitySignal{
			Plugin:          cachedir.Name,
			Justification:   vex.ComponentNotPresent,
			MatchesAllVulns: true,
		}},
	}}

	got := scalibr.New().Scan(t.Context(), cfg)

	if diff := cmp.Diff(wantPkgs, got.Inventory.Packages, fe.AllowUnexported); diff != "" {
		t.Errorf("scalibr.New().Scan(%v): unexpected diff (-want +got):\n%s", cfg, diff)
	}
}
