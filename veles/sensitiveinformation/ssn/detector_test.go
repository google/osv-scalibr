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

package ssn

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
)

func TestDetect_truePositives(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		want    []veles.Secret
		wantPos []int
	}{
		{
			name: "match_only",
			in:   []byte("123-45-6789"),
			want: []veles.Secret{
				ssnFinding([]byte("123-45-6789")),
			},
			wantPos: []int{0},
		},
		{
			name: "match_in_text",
			in:   []byte("ssn: 123-45-6789."),
			want: []veles.Secret{
				ssnFinding([]byte("123-45-6789")),
			},
			wantPos: []int{5},
		},
		{
			name: "starting_with_6",
			in:   []byte("ssn: 680-12-3456"),
			want: []veles.Secret{
				ssnFinding([]byte("680-12-3456")),
			},
			wantPos: []int{5},
		},
		{
			name: "double_9_in_the_middle",
			in:   []byte("ssn: 675-99-1234."),
			want: []veles.Secret{
				ssnFinding([]byte("675-99-1234")),
			},
			wantPos: []int{5},
		},
		{
			name: "multiple matches",
			in:   []byte("123-45-6789 001-01-0001"),
			want: []veles.Secret{
				ssnFinding([]byte("123-45-6789")),
				ssnFinding([]byte("001-01-0001")),
			},
			wantPos: []int{0, 12},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, gotPos := NewDetector().Detect(tc.in)
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantPos, gotPos, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() positions diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetect_trueNegatives(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{
			name: "no_match",
			in:   []byte("not an ssn"),
		},
		{
			name: "missing_dashes",
			in:   []byte("123456789"),
		},
		{
			name: "area_starts_with_666",
			in:   []byte("666-45-6789"),
		},
		{
			name: "area_starts_with_000",
			in:   []byte("000-45-6789"),
		},
		{
			name: "area_between_900_and_999",
			in:   []byte("900-45-6789"),
		},
		{
			name: "group_all_zeroes",
			in:   []byte("123-00-6789"),
		},
		{
			name: "serial_all_zeroes",
			in:   []byte("123-45-0000"),
		},

		{
			name: "area_starts_with_9h",
			in:   []byte("912-34-5678"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, gotPos := NewDetector().Detect(tc.in)
			if diff := cmp.Diff([]veles.Secret(nil), got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff([]int(nil), gotPos, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() positions diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetectorMaxSecretLen(t *testing.T) {
	if got, want := NewDetector().MaxSecretLen(), uint32(len("123-45-6789")); got != want {
		t.Errorf("MaxSecretLen() = %d, want %d", got, want)
	}
}

func ssnFinding(raw []byte) sensitiveinformation.SensitiveInformation {
	return sensitiveinformation.SensitiveInformation{
		InfoType: sensitiveinformation.InfoType{
			Name:        "Social Security Number",
			Sensitivity: sensitiveinformation.SensitivityLevelModerate,
		},
		Likelihood: sensitiveinformation.LikelihoodLikely,
		Raw:        raw,
	}
}
