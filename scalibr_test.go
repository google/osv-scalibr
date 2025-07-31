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

package scalibr_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/annotator/cachedir"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
	fd "github.com/google/osv-scalibr/testing/fakedetector"
	fen "github.com/google/osv-scalibr/testing/fakeenricher"
	fe "github.com/google/osv-scalibr/testing/fakeextractor"
	"github.com/google/osv-scalibr/version"
	"github.com/mohae/deepcopy"
)

func TestScan(t *testing.T) {
	success := &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}
	pluginFailure := "failed to run plugin"
	extFailure := &plugin.ScanStatus{
		Status:        plugin.ScanStatusFailed,
		FailureReason: "file.txt: " + pluginFailure,
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

	pkgName := "software"
	fakeExtractor := fe.New(
		"python/wheelegg", 1, []string{"file.txt"},
		map[string]fe.NamesErr{"file.txt": {Names: []string{pkgName}, Err: nil}},
	)
	pkg := &extractor.Package{
		Name:      pkgName,
		Locations: []string{"file.txt"},
		Plugins:   []string{fakeExtractor.Name()},
	}
	withLayerDetails := func(pkg *extractor.Package, ld *extractor.LayerDetails) *extractor.Package {
		pkg = deepcopy.Copy(pkg).(*extractor.Package)
		pkg.LayerDetails = ld
		return pkg
	}
	pkgWithLayerDetails := withLayerDetails(pkg, &extractor.LayerDetails{InBaseImage: true})
	pkgWithLayerDetails.Plugins = []string{fakeExtractor.Name()}
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
			): fen.InventoryAndErr{
				Inventory: &inventory.Inventory{
					Packages: []*extractor.Package{pkgWithLayerDetails},
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
			): fen.InventoryAndErr{
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

	testCases := []struct {
		desc string
		cfg  *scalibr.ScanConfig
		want *scalibr.ScanResult
	}{
		{
			desc: "Successful scan",
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
					Packages: []*extractor.Package{pkgWithLayerDetails},
					GenericFindings: []*inventory.GenericFinding{
						withDetectorName(finding, "detector"),
					},
				},
			},
		},
		{
			desc: "Global error",
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
			desc: "Extractor plugin failed",
			cfg: &scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fe.New("python/wheelegg", 1, []string{"file.txt"}, map[string]fe.NamesErr{"file.txt": {Names: nil, Err: errors.New(pluginFailure)}}),
					fd.New().WithName("detector").WithVersion(2).WithGenericFinding(finding),
				},
				ScanRoots: tmpRoot,
			},
			want: &scalibr.ScanResult{
				Version: version.ScannerVersion,
				Status:  success,
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
			desc: "Detector plugin failed",
			cfg: &scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fakeExtractor,
					fd.New().WithName("detector").WithVersion(2).WithErr(errors.New(pluginFailure)),
				},
				ScanRoots: tmpRoot,
			},
			want: &scalibr.ScanResult{
				Version: version.ScannerVersion,
				Status:  success,
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
			desc: "Enricher plugin failed",
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
				Status:  success,
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
			desc: "Missing scan roots causes error",
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
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := scalibr.New().Scan(context.Background(), tc.cfg)

			// We can't mock the time from here so we skip it in the comparison.
			tc.want.StartTime = got.StartTime
			tc.want.EndTime = got.EndTime

			if diff := cmp.Diff(tc.want, got, fe.AllowUnexported); diff != "" {
				t.Errorf("scalibr.New().Scan(%v): unexpected diff (-want +got):\n%s", tc.cfg, diff)
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
			name: "no required extractors",
			cfg: scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fd.New().WithName("foo"),
				},
			},
			wantPlugins: []string{"foo"},
		},
		{
			name: "required extractor in already enabled",
			cfg: scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fd.New().WithName("foo").WithRequiredExtractors("bar/baz"),
					fe.New("bar/baz", 0, nil, nil),
				},
			},
			wantPlugins: []string{"foo", "bar/baz"},
		},
		{
			name: "auto-loaded required extractor",
			cfg: scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fd.New().WithName("foo").WithRequiredExtractors("python/wheelegg"),
				},
			},
			wantPlugins: []string{"foo", "python/wheelegg"},
		},
		{
			name: "auto-loaded required extractor by enricher",
			cfg: scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fen.MustNew(t, &fen.Config{Name: "foo", RequiredPlugins: []string{"python/wheelegg"}}),
				},
			},
			wantPlugins: []string{"foo", "python/wheelegg"},
		},
		{
			name: "required extractor doesn't exist",
			cfg: scalibr.ScanConfig{
				Plugins: []plugin.Plugin{
					fd.New().WithName("foo").WithRequiredExtractors("bar/baz"),
				},
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
			desc: "requirements satisfied",
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
			desc: "one detector's requirements unsatisfied",
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
			desc: "one enrichers's requirements unsatisfied",
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
			desc: "both plugin's requirements unsatisfied",
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

			got := scalibr.New().Scan(context.Background(), cfg)

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

	cfg := &scalibr.ScanConfig{
		Plugins:   []plugin.Plugin{fakeExtractor, cachedir.New()},
		ScanRoots: tmpRoot,
	}

	wantPkgs := []*extractor.Package{{
		Name:      pkgName,
		Locations: []string{"tmp/file.txt"},
		Plugins:   []string{fakeExtractor.Name()},
		ExploitabilitySignals: []*vex.PackageExploitabilitySignal{&vex.PackageExploitabilitySignal{
			Plugin:          cachedir.Name,
			Justification:   vex.ComponentNotPresent,
			MatchesAllVulns: true,
		}},
	}}

	got := scalibr.New().Scan(context.Background(), cfg)

	if diff := cmp.Diff(wantPkgs, got.Inventory.Packages, fe.AllowUnexported); diff != "" {
		t.Errorf("scalibr.New().Scan(%v): unexpected diff (-want +got):\n%s", cfg, diff)
	}
}
