// Copyright 2024 Google LLC
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
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/plugin"
	scalibr "github.com/google/osv-scalibr"
	fd "github.com/google/osv-scalibr/testing/fakedetector"
	fe "github.com/google/osv-scalibr/testing/fakeextractor"
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

	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "file.txt"), []byte("Content"), 0644)

	invName := "software"
	inventory := &extractor.Inventory{
		Name:      invName,
		Locations: []string{"file.txt"},
		Extractor: "python/wheelegg",
	}
	finding := &detector.Finding{Adv: &detector.Advisory{ID: &detector.AdvisoryID{Reference: "CVE-1234"}}}

	testCases := []struct {
		desc string
		cfg  *scalibr.ScanConfig
		want *scalibr.ScanResult
	}{
		{
			desc: "Successful scan",
			cfg: &scalibr.ScanConfig{
				InventoryExtractors: []extractor.InventoryExtractor{
					fe.New("python/wheelegg", 1, []string{"file.txt"},
						map[string]fe.NamesErr{"file.txt": {[]string{invName}, nil}}),
				},
				Detectors: []detector.Detector{
					fd.New("detector", 2, finding, nil),
				},
				ScanRoot: tmp,
			},
			want: &scalibr.ScanResult{
				Status: success,
				PluginStatus: []*plugin.Status{
					&plugin.Status{Name: "detector", Version: 2, Status: success},
					&plugin.Status{Name: "python/wheelegg", Version: 1, Status: success},
				},
				Inventories: []*extractor.Inventory{inventory},
				Findings:    []*detector.Finding{withDetectorName(finding, "detector")},
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
				ScanRoot: tmp,
			},
			want: &scalibr.ScanResult{
				Status: &plugin.ScanStatus{
					Status:        plugin.ScanStatusFailed,
					FailureReason: "multiple non-identical advisories with ID &{ CVE-1234}",
				},
				PluginStatus: []*plugin.Status{
					&plugin.Status{Name: "detector", Version: 2, Status: success},
					&plugin.Status{Name: "detector", Version: 3, Status: success},
				},
				Inventories: []*extractor.Inventory{},
				Findings:    []*detector.Finding{},
			},
		},
		{
			desc: "Extractor plugin failed",
			cfg: &scalibr.ScanConfig{
				InventoryExtractors: []extractor.InventoryExtractor{
					fe.New("python/wheelegg", 1, []string{"file.txt"}, map[string]fe.NamesErr{"file.txt": {nil, errors.New(pluginFailure)}}),
				},
				Detectors: []detector.Detector{fd.New("detector", 2, finding, nil)},
				ScanRoot:  tmp,
			},
			want: &scalibr.ScanResult{
				Status: success,
				PluginStatus: []*plugin.Status{
					&plugin.Status{Name: "detector", Version: 2, Status: success},
					&plugin.Status{Name: "python/wheelegg", Version: 1, Status: extFailure},
				},
				Inventories: []*extractor.Inventory{},
				Findings:    []*detector.Finding{withDetectorName(finding, "detector")},
			},
		},
		{
			desc: "Detector plugin failed",
			cfg: &scalibr.ScanConfig{
				InventoryExtractors: []extractor.InventoryExtractor{
					fe.New("python/wheelegg", 1, []string{"file.txt"},
						map[string]fe.NamesErr{"file.txt": {[]string{invName}, nil}}),
				},
				Detectors: []detector.Detector{
					fd.New("detector", 2, nil, errors.New(pluginFailure)),
				},
				ScanRoot: tmp,
			},
			want: &scalibr.ScanResult{
				Status: success,
				PluginStatus: []*plugin.Status{
					&plugin.Status{Name: "detector", Version: 2, Status: detFailure},
					&plugin.Status{Name: "python/wheelegg", Version: 1, Status: success},
				},
				Inventories: []*extractor.Inventory{inventory},
				Findings:    []*detector.Finding{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := scalibr.New().Scan(context.Background(), tc.cfg)

			// We can't mock the time from here so we skip it in the comparison.
			tc.want.StartTime = got.StartTime
			tc.want.EndTime = got.EndTime

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("scalibr.New().Scan(%v): unexpected diff (-want +got):\n%s", tc.cfg, diff)
			}
		})
	}
}

func withDetectorName(f *detector.Finding, det string) *detector.Finding {
	copy := *f
	copy.Detectors = []string{det}
	return &copy
}
