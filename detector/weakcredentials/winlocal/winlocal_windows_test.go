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

//go:build windows

package winlocal

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestInternalScan(t *testing.T) {
	tests := []struct {
		name                       string
		hashes                     []*userHashInfo
		wantErr                    error
		expectedFindingsReferences []string
	}{
		{
			name: "no_hashes_returns_no_findings",
			hashes: []*userHashInfo{
				&userHashInfo{
					lmHash: "",
					ntHash: "",
				},
			},
			expectedFindingsReferences: nil,
		},
		{
			name: "lm_hash_returns_lm_finding",
			hashes: []*userHashInfo{
				&userHashInfo{
					lmHash: "irrelevant",
					ntHash: "irrelevant",
				},
			},
			expectedFindingsReferences: []string{
				vulnRefLMPassword,
			},
		},
		{
			name: "weak_password_returns_finding",
			hashes: []*userHashInfo{
				&userHashInfo{
					lmHash: "",
					ntHash: "329153F560EB329C0E1DEEA55E88A1E9", // root
				},
			},
			expectedFindingsReferences: []string{
				vulnRefWeakPass,
			},
		},
		{
			name: "weak_password_and_lm_hash_returns_findings",
			hashes: []*userHashInfo{
				&userHashInfo{
					lmHash: "D480EA9533C500D4AAD3B435B51404EE", // root
					ntHash: "329153F560EB329C0E1DEEA55E88A1E9", // root
				},
			},
			expectedFindingsReferences: []string{
				vulnRefLMPassword,
				vulnRefWeakPass,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := Detector{}
			findings, err := d.internalScan(t.Context(), tc.hashes)
			if err != nil {
				t.Fatalf("internalScan(...) unexpected error, got: %v, want: %v", err, tc.wantErr)
			}

			for _, finding := range findings {
				if !slices.Contains(tc.expectedFindingsReferences, finding.Adv.ID.Reference) {
					t.Errorf("internalScan(...) unexpected finding, got: %v, want: %v", finding.Adv.ID.Reference, tc.expectedFindingsReferences)
				}
			}
		})
	}
}

func TestBruteforce(t *testing.T) {
	tests := []struct {
		name    string
		hashes  []*userHashInfo
		wantMap map[string]string
	}{
		{
			name: "no_hashes_returns_no_findings",
			hashes: []*userHashInfo{
				&userHashInfo{
					username: "user",
					lmHash:   "",
					ntHash:   "",
				},
			},
			wantMap: map[string]string{},
		},
		{
			name: "lm_not_weak_returns_no_finding",
			hashes: []*userHashInfo{
				&userHashInfo{
					username: "root",
					lmHash:   "978A0A1C20E21F373757F7116254AD0B", // AVeryComplexPassword
					ntHash:   "",
				},
			},
			wantMap: map[string]string{},
		},
		{
			name: "nt_weak_password_returns_finding",
			hashes: []*userHashInfo{
				&userHashInfo{
					username: "root",
					lmHash:   "",
					ntHash:   "0CB6948805F797BF2A82807973B89537", // test
				},
			},
			wantMap: map[string]string{
				"root": "test",
			},
		},
		{
			name: "nt_not_weak_returns_no_finding",
			hashes: []*userHashInfo{
				&userHashInfo{
					username: "root",
					lmHash:   "",
					ntHash:   "D5F234DB9AA96CEAC168598BB576C7A6", // AVeryComplexPassword
				},
			},
			wantMap: map[string]string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := Detector{}
			gotMap, err := d.bruteforce(t.Context(), tc.hashes)
			if err != nil {
				t.Fatalf("bruteforce(...) unexpected error: %v", err)
			}

			if diff := cmp.Diff(gotMap, tc.wantMap); diff != "" {
				t.Errorf("bruteforce(...) unexpected diff (-want +got): %v", diff)
			}
		})
	}
}
