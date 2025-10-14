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

package detectorrunner_test

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/detector/detectorrunner"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"
	fd "github.com/google/osv-scalibr/testing/fakedetector"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestRun(t *testing.T) {
	finding1 := &inventory.GenericFinding{
		Adv: &inventory.GenericFindingAdvisory{
			ID: &inventory.AdvisoryID{
				Publisher: "CVE",
				Reference: "CVE-1234",
			},
			Sev: inventory.SeverityMedium,
		},
	}
	identicalFinding1 := &inventory.GenericFinding{
		Adv: &inventory.GenericFindingAdvisory{
			ID: &inventory.AdvisoryID{
				Publisher: "CVE",
				Reference: "CVE-1234",
			},
			Sev: inventory.SeverityMedium,
		},
	}
	finding2 := &inventory.GenericFinding{
		Adv: &inventory.GenericFindingAdvisory{
			ID: &inventory.AdvisoryID{
				Publisher: "CVE",
				Reference: "CVE-5678",
			},
		},
	}
	findingNoAdvisory := &inventory.GenericFinding{}
	findingNoAdvisoryID := &inventory.GenericFinding{Adv: &inventory.GenericFindingAdvisory{}}
	packageVuln := &inventory.PackageVuln{
		Vulnerability: osvschema.Vulnerability{Id: "CVE-9012"},
	}
	det1 := fd.New().WithName("det1").WithVersion(1)
	det2 := fd.New().WithName("det2").WithVersion(2)
	success := &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}

	testCases := []struct {
		desc         string
		det          []detector.Detector
		wantFindings inventory.Finding
		wantStatus   []*plugin.Status
		wantErr      error
	}{
		{
			desc: "Plugins successful",
			det: []detector.Detector{
				det1.WithGenericFinding(finding1),
				det2.WithGenericFinding(finding2),
			},
			wantFindings: inventory.Finding{
				GenericFindings: []*inventory.GenericFinding{
					withDetectorName(finding1, "det1"),
					withDetectorName(finding2, "det2"),
				},
			},
			wantStatus: []*plugin.Status{
				{Name: "det1", Version: 1, Status: success},
				{Name: "det2", Version: 2, Status: success},
			},
		},
		{
			desc: "One plugin failed",
			det: []detector.Detector{
				det1.WithGenericFinding(finding1),
				det2.WithErr(errors.New("detection failed")),
			},
			wantFindings: inventory.Finding{
				GenericFindings: []*inventory.GenericFinding{withDetectorName(finding1, "det1")},
			},
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
				det1.WithGenericFinding(finding1),
				det2.WithGenericFinding(identicalFinding1),
			},
			wantFindings: inventory.Finding{GenericFindings: []*inventory.GenericFinding{
				withDetectorName(finding1, "det1"),
				withDetectorName(finding1, "det2"),
			}},
			wantStatus: []*plugin.Status{
				{Name: "det1", Version: 1, Status: success},
				{Name: "det2", Version: 2, Status: success},
			},
		},
		{
			desc: "Duplicate findings with different advisories",
			det: []detector.Detector{
				det1.WithGenericFinding(finding1),
				det2.WithGenericFinding(&inventory.GenericFinding{
					Adv: &inventory.GenericFindingAdvisory{ID: finding1.Adv.ID, Title: "different title"},
				}),
			},
			wantFindings: inventory.Finding{},
			wantStatus: []*plugin.Status{
				{Name: "det1", Version: 1, Status: success},
				{Name: "det2", Version: 2, Status: success},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Error when Advisory is not set",
			det: []detector.Detector{
				det1.WithGenericFinding(findingNoAdvisory),
			},
			wantFindings: inventory.Finding{},
			wantStatus: []*plugin.Status{
				{Name: "det1", Version: 1, Status: success},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Error when Advisory ID is not set",
			det: []detector.Detector{
				det1.WithGenericFinding(findingNoAdvisoryID),
			},
			wantFindings: inventory.Finding{},
			wantStatus: []*plugin.Status{
				{Name: "det1", Version: 1, Status: success},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Package and generic vulns",
			det: []detector.Detector{
				det1.WithGenericFinding(finding1),
				det2.WithPackageVuln(packageVuln),
			},
			wantFindings: inventory.Finding{
				GenericFindings: []*inventory.GenericFinding{withDetectorName(finding1, "det1")},
				PackageVulns:    []*inventory.PackageVuln{pkgVulnWithDetectorName(packageVuln, "det2")},
			},
			wantStatus: []*plugin.Status{
				{Name: "det1", Version: 1, Status: success},
				{Name: "det2", Version: 2, Status: success},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			px, _ := packageindex.New([]*extractor.Package{})
			tmp := t.TempDir()
			gotFindings, gotStatus, err := detectorrunner.Run(
				t.Context(), stats.NoopCollector{}, tc.det, scalibrfs.RealFSScanRoot(tmp), px,
			)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("detectorrunner.Run(%v): unexpected error (-want +got):\n%s", tc.det, diff)
			}
			if diff := cmp.Diff(tc.wantFindings, gotFindings, protocmp.Transform()); diff != "" {
				t.Errorf("detectorrunner.Run(%v): unexpected findings (-want +got):\n%s", tc.det, diff)
			}
			if diff := cmp.Diff(tc.wantStatus, gotStatus); diff != "" {
				t.Errorf("detectorrunner.Run(%v): unexpected status (-want +got):\n%s", tc.det, diff)
			}
		})
	}
}

func withDetectorName(f *inventory.GenericFinding, det string) *inventory.GenericFinding {
	c := *f
	c.Plugins = []string{det}
	return &c
}

func pkgVulnWithDetectorName(v *inventory.PackageVuln, det string) *inventory.PackageVuln {
	c := *v
	c.Plugins = []string{det}
	return &c
}
