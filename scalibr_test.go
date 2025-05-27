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
	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/cachedir"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	fd "github.com/google/osv-scalibr/testing/fakedetector"
	fen "github.com/google/osv-scalibr/testing/fakeenricher"
	fe "github.com/google/osv-scalibr/testing/fakeextractor"
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
		Extractor: fakeExtractor,
	}
	withLayerDetails := func(pkg *extractor.Package, ld *extractor.LayerDetails) *extractor.Package {
		pkg = deepcopy.Copy(pkg).(*extractor.Package)
		pkg.LayerDetails = ld
		return pkg
	}
	pkgWithLayerDetails := withLayerDetails(pkg, &extractor.LayerDetails{InBaseImage: true})
	pkgWithLayerDetails.Extractor = fakeExtractor
	finding := &detector.Finding{Adv: &detector.Advisory{ID: &detector.AdvisoryID{Reference: "CVE-1234"}}}

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
					Findings: []*detector.Finding{withDetectorName(finding, "detector")},
				},
			): fen.InventoryAndErr{
				Inventory: &inventory.Inventory{
					Packages: []*extractor.Package{pkgWithLayerDetails},
					Findings: []*detector.Finding{withDetectorName(finding, "detector")},
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
					Findings: []*detector.Finding{withDetectorName(finding, "detector2")},
				},
			): fen.InventoryAndErr{
				Inventory: &inventory.Inventory{
					Packages: []*extractor.Package{pkg},
					Findings: []*detector.Finding{withDetectorName(finding, "detector2")},
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
				FilesystemExtractors: []filesystem.Extractor{fakeExtractor},
				Detectors: []detector.Detector{
					fd.New("detector", 2, finding, nil),
				},
				Enrichers: []enricher.Enricher{fakeEnricher},
				ScanRoots: tmpRoot,
			},
			want: &scalibr.ScanResult{
				Version: scalibr.ScannerVersion,
				Status:  success,
				PluginStatus: []*plugin.Status{
					{Name: "detector", Version: 2, Status: success},
					{Name: "enricher", Version: 1, Status: success},
					{Name: "python/wheelegg", Version: 1, Status: success},
				},
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{pkgWithLayerDetails},
					Findings: []*detector.Finding{withDetectorName(finding, "detector")},
				},
			},
		},
		{
			desc: "Global error",
			cfg: &scalibr.ScanConfig{
				Detectors: []detector.Detector{
					// Will error due to duplicate non-identical Advisories.
					fd.New("detector", 2, finding, nil),
					fd.New("detector", 3, &detector.Finding{
						Adv: &detector.Advisory{ID: finding.Adv.ID, Title: "different title"},
					}, nil),
				},
				ScanRoots: tmpRoot,
			},
			want: &scalibr.ScanResult{
				Version: scalibr.ScannerVersion,
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
				FilesystemExtractors: []filesystem.Extractor{
					fe.New("python/wheelegg", 1, []string{"file.txt"}, map[string]fe.NamesErr{"file.txt": {Names: nil, Err: errors.New(pluginFailure)}}),
				},
				Detectors: []detector.Detector{fd.New("detector", 2, finding, nil)},
				ScanRoots: tmpRoot,
			},
			want: &scalibr.ScanResult{
				Version: scalibr.ScannerVersion,
				Status:  success,
				PluginStatus: []*plugin.Status{
					{Name: "detector", Version: 2, Status: success},
					{Name: "python/wheelegg", Version: 1, Status: extFailure},
				},
				Inventory: inventory.Inventory{
					Packages: nil,
					Findings: []*detector.Finding{withDetectorName(finding, "detector")},
				},
			},
		},
		{
			desc: "Detector plugin failed",
			cfg: &scalibr.ScanConfig{
				FilesystemExtractors: []filesystem.Extractor{fakeExtractor},
				Detectors: []detector.Detector{
					fd.New("detector", 2, nil, errors.New(pluginFailure)),
				},
				ScanRoots: tmpRoot,
			},
			want: &scalibr.ScanResult{
				Version: scalibr.ScannerVersion,
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
				FilesystemExtractors: []filesystem.Extractor{fakeExtractor},
				Detectors: []detector.Detector{
					fd.New("detector2", 2, finding, nil),
				},
				Enrichers: []enricher.Enricher{fakeEnricherErr},
				ScanRoots: tmpRoot,
			},
			want: &scalibr.ScanResult{
				Version: scalibr.ScannerVersion,
				Status:  success,
				PluginStatus: []*plugin.Status{
					{Name: "detector2", Version: 2, Status: success},
					{Name: "enricher", Version: 1, Status: enrFailure},
					{Name: "python/wheelegg", Version: 1, Status: success},
				},
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{pkg},
					Findings: []*detector.Finding{withDetectorName(finding, "detector2")},
				},
			},
		},
		{
			desc: "Missing scan roots causes error",
			cfg: &scalibr.ScanConfig{
				FilesystemExtractors: []filesystem.Extractor{fakeExtractor},
				ScanRoots:            []*scalibrfs.ScanRoot{},
			},
			want: &scalibr.ScanResult{
				Version: scalibr.ScannerVersion,
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

func withDetectorName(f *detector.Finding, det string) *detector.Finding {
	c := *f
	c.Detectors = []string{det}
	return &c
}

func TestEnableRequiredExtractors(t *testing.T) {
	cases := []struct {
		name           string
		cfg            scalibr.ScanConfig
		wantExtractors []string
		wantErr        error
	}{
		{
			name: "empty",
		},
		{
			name: "no required extractors",
			cfg: scalibr.ScanConfig{
				Detectors: []detector.Detector{
					fd.NewWithOptions(fd.WithName("foo")),
				},
			},
		},
		{
			name: "required extractor in already enabled",
			cfg: scalibr.ScanConfig{
				Detectors: []detector.Detector{
					fd.NewWithOptions(fd.WithName("foo"), fd.WithRequiredExtractors("bar/baz")),
				},
				FilesystemExtractors: []filesystem.Extractor{
					fe.New("bar/baz", 0, nil, nil),
				},
			},
			wantExtractors: []string{"bar/baz"},
		},
		{
			name: "auto-loaded required extractor",
			cfg: scalibr.ScanConfig{
				Detectors: []detector.Detector{
					fd.NewWithOptions(fd.WithName("foo"), fd.WithRequiredExtractors("python/wheelegg")),
				},
			},
			wantExtractors: []string{"python/wheelegg"},
		},
		{
			name: "auto-loaded required extractor by enricher",
			cfg: scalibr.ScanConfig{
				Enrichers: []enricher.Enricher{
					fen.MustNew(t, &fen.Config{RequiredPlugins: []string{"python/wheelegg"}}),
				},
			},
			wantExtractors: []string{"python/wheelegg"},
		},
		{
			name: "required extractor doesn't exist",
			cfg: scalibr.ScanConfig{
				Detectors: []detector.Detector{
					fd.NewWithOptions(fd.WithName("foo"), fd.WithRequiredExtractors("bar/baz")),
				},
			},
			wantErr: cmpopts.AnyError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.EnableRequiredExtractors(); !cmp.Equal(tc.wantErr, err, cmpopts.EquateErrors()) {
				t.Fatalf("EnableRequiredExtractors() error: %v, want %v", tc.wantErr, err)
			}
			if tc.wantErr == nil {
				gotExtractors := []string{}
				for _, e := range tc.cfg.FilesystemExtractors {
					gotExtractors = append(gotExtractors, e.Name())
				}
				for _, e := range tc.cfg.StandaloneExtractors {
					gotExtractors = append(gotExtractors, e.Name())
				}
				if diff := cmp.Diff(
					tc.wantExtractors,
					gotExtractors,
					cmpopts.EquateEmpty(),
					cmpopts.SortSlices(func(l, r string) bool { return l < r }),
				); diff != "" {
					t.Errorf("EnableRequiredExtractors() diff (-want, +got):\n%s", diff)
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
func (e fakeExNeedsNetwork) ToPURL(p *extractor.Package) *purl.PackageURL { return nil }
func (e fakeExNeedsNetwork) Ecosystem(p *extractor.Package) string        { return "" }

func (fakeExNeedsNetwork) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{Network: plugin.NetworkOnline}
}

type fakeDetNeedsFS struct {
}

func (fakeDetNeedsFS) Name() string                 { return "fake-extractor" }
func (fakeDetNeedsFS) Version() int                 { return 0 }
func (fakeDetNeedsFS) RequiredExtractors() []string { return nil }
func (fakeDetNeedsFS) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) ([]*detector.Finding, error) {
	return nil, nil
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
				FilesystemExtractors: []filesystem.Extractor{
					&fakeExNeedsNetwork{},
				},
				Detectors: []detector.Detector{
					&fakeDetNeedsFS{},
				},
				Enrichers: []enricher.Enricher{
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
				FilesystemExtractors: []filesystem.Extractor{
					&fakeExNeedsNetwork{},
				},
				Detectors: []detector.Detector{
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
				FilesystemExtractors: []filesystem.Extractor{
					&fakeExNeedsNetwork{},
				},
				Enrichers: []enricher.Enricher{
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
				FilesystemExtractors: []filesystem.Extractor{
					&fakeExNeedsNetwork{},
				},
				Detectors: []detector.Detector{
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
				FilesystemExtractors: []filesystem.Extractor{
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
		FilesystemExtractors: []filesystem.Extractor{fakeExtractor},
		Annotators:           []annotator.Annotator{cachedir.New()},
		ScanRoots:            tmpRoot,
	}

	wantPkgs := []*extractor.Package{{
		Name:        pkgName,
		Locations:   []string{"tmp/file.txt"},
		Extractor:   fakeExtractor,
		Annotations: []extractor.Annotation{extractor.InsideCacheDir},
	}}

	got := scalibr.New().Scan(context.Background(), cfg)

	if diff := cmp.Diff(wantPkgs, got.Inventory.Packages, fe.AllowUnexported); diff != "" {
		t.Errorf("scalibr.New().Scan(%v): unexpected diff (-want +got):\n%s", cfg, diff)
	}
}
