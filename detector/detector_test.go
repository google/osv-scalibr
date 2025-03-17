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

package detector_test

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventoryindex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"
	fd "github.com/google/osv-scalibr/testing/fakedetector"
)

func TestRun(t *testing.T) {
	finding1 := &detector.Finding{
		Adv: &detector.Advisory{
			ID: &detector.AdvisoryID{
				Publisher: "CVE",
				Reference: "CVE-1234",
			},
			Sev: &detector.Severity{Severity: detector.SeverityMedium},
		},
	}
	identicalFinding1 := &detector.Finding{
		Adv: &detector.Advisory{
			ID: &detector.AdvisoryID{
				Publisher: "CVE",
				Reference: "CVE-1234",
			},
			Sev: &detector.Severity{Severity: detector.SeverityMedium},
		},
	}
	finding2 := &detector.Finding{
		Adv: &detector.Advisory{
			ID: &detector.AdvisoryID{
				Publisher: "CVE",
				Reference: "CVE-5678",
			},
		},
	}
	findingNoAdvisory := &detector.Finding{}
	findingNoAdvisoryID := &detector.Finding{Adv: &detector.Advisory{}}
	success := &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}

	testCases := []struct {
		desc         string
		det          []detector.Detector
		wantFindings []*detector.Finding
		wantStatus   []*plugin.Status
		wantErr      error
	}{
		{
			desc: "Plugins successful",
			det: []detector.Detector{
				fd.New("det1", 1, finding1, nil),
				fd.New("det2", 2, finding2, nil),
			},
			wantFindings: []*detector.Finding{
				withDetectorName(finding1, "det1"),
				withDetectorName(finding2, "det2"),
			},
			wantStatus: []*plugin.Status{
				{Name: "det1", Version: 1, Status: success},
				{Name: "det2", Version: 2, Status: success},
			},
		},
		{
			desc: "One plugin failed",
			det: []detector.Detector{
				fd.New("det1", 1, finding1, nil),
				fd.New("det2", 2, nil, errors.New("detection failed")),
			},
			wantFindings: []*detector.Finding{withDetectorName(finding1, "det1")},
			wantStatus: []*plugin.Status{
				{Name: "det1", Version: 1, Status: success},
				{Name: "det2", Version: 2, Status: &plugin.ScanStatus{
					Status: plugin.ScanStatusFailed, FailureReason: "detection failed",
				}},
			},
		},
		{
			desc: "Duplicate findings with identical advisories",
			det: []detector.Detector{
				fd.New("det1", 1, finding1, nil),
				fd.New("det2", 2, identicalFinding1, nil),
			},
			wantFindings: []*detector.Finding{withDetectorName(finding1, "det1"), withDetectorName(finding1, "det2")},
			wantStatus: []*plugin.Status{
				{Name: "det1", Version: 1, Status: success},
				{Name: "det2", Version: 2, Status: success},
			},
		},
		{
			desc: "Duplicate findings with different advisories",
			det: []detector.Detector{
				fd.New("det1", 1, finding1, nil),
				fd.New("det2", 2, &detector.Finding{
					Adv: &detector.Advisory{ID: finding1.Adv.ID, Title: "different title"},
				}, nil),
			},
			wantFindings: []*detector.Finding{},
			wantStatus: []*plugin.Status{
				{Name: "det1", Version: 1, Status: success},
				{Name: "det2", Version: 2, Status: success},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Error when Advisory is not set",
			det: []detector.Detector{
				fd.New("det1", 1, findingNoAdvisory, nil),
			},
			wantFindings: []*detector.Finding{},
			wantStatus: []*plugin.Status{
				{Name: "det1", Version: 1, Status: success},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Error when Advisory ID is not set",
			det: []detector.Detector{
				fd.New("det1", 1, findingNoAdvisoryID, nil),
			},
			wantFindings: []*detector.Finding{},
			wantStatus: []*plugin.Status{
				{Name: "det1", Version: 1, Status: success},
			},
			wantErr: cmpopts.AnyError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ix, _ := inventoryindex.New([]*extractor.Inventory{})
			tmp := t.TempDir()
			gotFindings, gotStatus, err := detector.Run(
				t.Context(), stats.NoopCollector{}, tc.det, scalibrfs.RealFSScanRoot(tmp), ix,
			)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("detector.Run(%v): unexpected error (-want +got):\n%s", tc.det, diff)
			}
			if diff := cmp.Diff(tc.wantFindings, gotFindings); diff != "" {
				t.Errorf("detector.Run(%v): unexpected findings (-want +got):\n%s", tc.det, diff)
			}
			if diff := cmp.Diff(tc.wantStatus, gotStatus); diff != "" {
				t.Errorf("detector.Run(%v): unexpected status (-want +got):\n%s", tc.det, diff)
			}
		})
	}
}

func withDetectorName(f *detector.Finding, det string) *detector.Finding {
	c := *f
	c.Detectors = []string{det}
	return &c
}
