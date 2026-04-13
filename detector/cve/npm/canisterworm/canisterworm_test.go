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

package canisterworm

import (
	"context"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/purl"
)

func TestScan(t *testing.T) {
	tests := []struct {
		name      string
		packages  []*extractor.Package
		wantCount int
	}{
		{
			name: "malicious package found",
			packages: []*extractor.Package{
				{Name: "@leafnoise/mirage", Version: "2.0.3", PURLType: purl.TypeNPM},
			},
			wantCount: 1,
		},
		{
			name: "malicious pypi package found",
			packages: []*extractor.Package{
				{Name: "telnyx", Version: "4.87.1", PURLType: purl.TypePyPi},
			},
			wantCount: 1,
		},
		{
			name: "multiple versions of malicious package",
			packages: []*extractor.Package{
				{Name: "@emilgroup/setting-sdk", Version: "0.2.3", PURLType: purl.TypeNPM},
				{Name: "@emilgroup/setting-sdk", Version: "0.2.1", PURLType: purl.TypeNPM},
			},
			wantCount: 2,
		},
		{
			name: "clean version of malicious package",
			packages: []*extractor.Package{
				{Name: "@leafnoise/mirage", Version: "2.0.4", PURLType: purl.TypeNPM},
			},
			wantCount: 0,
		},
		{
			name: "clean packages found",
			packages: []*extractor.Package{
				{Name: "express", Version: "4.17.1", PURLType: purl.TypeNPM},
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Detector{}
			px, err := packageindex.New(tt.packages)
			if err != nil {
				t.Fatalf("packageindex.New() error = %v", err)
			}
			got, err := d.Scan(context.Background(), nil, px)
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}

			if len(got.GenericFindings) != tt.wantCount {
				t.Errorf("Scan() got %d findings, want %d", len(got.GenericFindings), tt.wantCount)
			}
		})
	}
}

func TestDetectedFinding(t *testing.T) {
	d := Detector{}
	got := d.DetectedFinding()

	if len(got.GenericFindings) != 1 {
		t.Errorf("DetectedFinding() got %d findings, want %d", len(got.GenericFindings), 1)
	}

	if len(got.GenericFindings) > 0 {
		wantTitle := "Malicious version of package detected"
		if got.GenericFindings[0].Adv.Title != wantTitle {
			t.Errorf("DetectedFinding() summary = %q, want %q", got.GenericFindings[0].Adv.Title, wantTitle)
		}
	}
}
