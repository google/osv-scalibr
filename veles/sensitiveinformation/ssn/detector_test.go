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
	"bytes"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"github.com/google/osv-scalibr/veles/velestest"
)

const testSsn = "321-12-1234"

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		NewDetector(),
		testSsn,
		ssnFinding([]byte("321-12-1234")),
	)
}

func TestDetect_truePositives(t *testing.T) {
	e, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		in   []byte
		want []veles.Secret
	}{
		{
			name: "match_only",
			in:   []byte("223-45-6789"),
			want: []veles.Secret{
				ssnFinding([]byte("223-45-6789")),
			},
		},
		{
			name: "match_unformatted",
			in:   []byte("223456789"),
			want: []veles.Secret{
				ssnFinding([]byte("223456789")),
			},
		},
		{
			name: "match_spaced",
			in:   []byte("223 45 6789"),
			want: []veles.Secret{
				ssnFinding([]byte("223 45 6789")),
			},
		},
		{
			name: "match_in_text",
			in:   []byte("ssn: 133-45-6789."),
			want: []veles.Secret{
				ssnFindingWithLikelihood([]byte("133-45-6789"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "unformatted_with_keyword",
			in:   []byte("ssn: 133456789"),
			want: []veles.Secret{
				ssnFindingWithLikelihood([]byte("133456789"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "spaced_with_keyword",
			in:   []byte("ssn: 133 45 6789"),
			want: []veles.Secret{
				ssnFindingWithLikelihood([]byte("133 45 6789"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "starting_with_6",
			in:   []byte("ssn: 680-62-6456"),
			want: []veles.Secret{
				ssnFindingWithLikelihood([]byte("680-62-6456"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "double_9_in_the_middle",
			in:   []byte("ssn: 675-99-1234."),
			want: []veles.Secret{
				ssnFindingWithLikelihood([]byte("675-99-1234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "keyword_before",
			in:   []byte("social security number: 431-12-1234"),
			want: []veles.Secret{
				ssnFindingWithLikelihood([]byte("431-12-1234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "keyword_after",
			in:   []byte("431-12-1234 social security"),
			want: []veles.Secret{
				ssnFindingWithLikelihood([]byte("431-12-1234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "socialsecuritynumber_keyword",
			in:   []byte("socialsecuritynumber: 431-12-1234"),
			want: []veles.Secret{
				ssnFindingWithLikelihood([]byte("431-12-1234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "socialsecurity_keyword",
			in:   []byte("socialsecurity: 431-12-1234"),
			want: []veles.Secret{
				ssnFindingWithLikelihood([]byte("431-12-1234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "multiple_matches",
			in:   []byte("223-45-6789 001010001 331 12 4321"),
			want: []veles.Secret{
				ssnFinding([]byte("223-45-6789")),
				ssnFinding([]byte("001010001")),
				ssnFinding([]byte("331 12 4321")),
			},
		},
		// Useful to catch the lack of bytes.Clone()
		{
			name: "multiple_matches_long_gap",
			in:   []byte("223-45-6789" + strings.Repeat(" ", 50000) + "001-01-0001"),
			want: []veles.Secret{
				ssnFinding([]byte("223-45-6789")),
				ssnFinding([]byte("001-01-0001")),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, derr := e.Detect(t.Context(), bytes.NewBuffer(tc.in))
			if derr != nil {
				t.Fatal(derr)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetect_trueNegatives(t *testing.T) {
	e, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

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
			in:   []byte("123 45-6789"),
		},
		{
			name: "too_long",
			in:   []byte("2234567890"),
		},
		{
			name: "area_starts_with_666",
			in:   []byte("666-45-6789"),
		},
		{
			name: "unformatted_area_starts_with_666",
			in:   []byte("666456789"),
		},
		{
			name: "spaced_area_starts_with_666",
			in:   []byte("666 45 6789"),
		},
		{
			name: "area_starts_with_000",
			in:   []byte("000-45-6789"),
		},
		{
			name: "unformatted_area_starts_with_000",
			in:   []byte("000456789"),
		},
		{
			name: "spaced_area_starts_with_000",
			in:   []byte("000 45 6789"),
		},
		{
			name: "area_between_900_and_999",
			in:   []byte("900-45-6789"),
		},
		{
			name: "unformatted_area_between_900_and_999",
			in:   []byte("900456789"),
		},
		{
			name: "spaced_area_between_900_and_999",
			in:   []byte("900 45 6789"),
		},
		{
			name: "group_all_zeroes",
			in:   []byte("123-00-6789"),
		},
		{
			name: "unformatted_group_all_zeroes",
			in:   []byte("123006789"),
		},
		{
			name: "spaced_group_all_zeroes",
			in:   []byte("123 00 6789"),
		},
		{
			name: "serial_all_zeroes",
			in:   []byte("123-45-0000"),
		},
		{
			name: "unformatted_serial_all_zeroes",
			in:   []byte("123450000"),
		},
		{
			name: "spaced_serial_all_zeroes",
			in:   []byte("123 45 0000"),
		},
		{
			name: "area_starts_with_9",
			in:   []byte("912-34-5678"),
		},
		{
			name: "within_longer_string",
			in:   []byte("asdf123-45-6789asdf"),
		},
		{
			name: "placeholder_pattern_123",
			in:   []byte("123-45-6789"),
		},
		{
			name: "unformatted_placeholder_pattern_123",
			in:   []byte("123456789"),
		},
		{
			name: "spaced_placeholder_pattern_123",
			in:   []byte("123 45 6789"),
		},
		{
			name: "placeholder_pattern_111",
			in:   []byte("111-11-1111"),
		},
		{
			name: "unformatted_placeholder_pattern_111",
			in:   []byte("111111111"),
		},
		{
			name: "spaced_placeholder_pattern_111",
			in:   []byte("111 11 1111"),
		},
		{
			name: "placeholder_pattern_woolworth",
			in:   []byte("078-05-1120"),
		},
		{
			name: "unformatted_placeholder_pattern_woolworth",
			in:   []byte("078051120"),
		},
		{
			name: "spaced_placeholder_pattern_woolworth",
			in:   []byte("078 05 1120"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, derr := e.Detect(t.Context(), bytes.NewBuffer(tc.in))
			if derr != nil {
				t.Fatal(derr)
			}
			if diff := cmp.Diff([]veles.Secret(nil), got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetectorMaxSecretLen(t *testing.T) {
	if got, want := NewDetector().MaxSecretLen(), uint32(len("123-45-6789")+(2*contextWindowSize)); got != want {
		t.Errorf("MaxSecretLen() = %d, want %d", got, want)
	}
}

func ssnFinding(raw []byte) sensitiveinformation.SensitiveInformation {
	return ssnFindingWithLikelihood(raw, sensitiveinformation.LikelihoodUnlikely)
}

func ssnFindingWithLikelihood(raw []byte, likelihood sensitiveinformation.Likelihood) sensitiveinformation.SensitiveInformation {
	return sensitiveinformation.SensitiveInformation{
		InfoType: sensitiveinformation.InfoType{
			Name:        "SOCIAL_SECURITY_NUMBER",
			Sensitivity: sensitiveinformation.SensitivityLevelHigh,
		},
		Likelihood: likelihood,
		Raw:        raw,
	}
}
