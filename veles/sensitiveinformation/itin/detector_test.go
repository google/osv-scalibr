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

package itin

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

const testItin = "900-70-1234"

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		NewDetector(),
		testItin,
		itinFinding([]byte(testItin)),
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
			in:   []byte("900-70-1234"),
			want: []veles.Secret{
				itinFinding([]byte("900-70-1234")),
			},
		},
		{
			name: "match_without_dashes",
			in:   []byte("900701234"),
			want: []veles.Secret{
				itinFinding([]byte("900701234")),
			},
		},
		{
			name: "keyword_before",
			in:   []byte("itin: 900-50-1234"),
			want: []veles.Secret{
				itinFindingWithLikelihood([]byte("900-50-1234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "unformatted_with_keyword",
			in:   []byte("itin: 900501234"),
			want: []veles.Secret{
				itinFindingWithLikelihood([]byte("900501234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "keyword_after",
			in:   []byte("900-65-1234 individual taxpayer identification number"),
			want: []veles.Secret{
				itinFindingWithLikelihood([]byte("900-65-1234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "unformatted_keyword_after",
			in:   []byte("900651234 individual taxpayer identification number"),
			want: []veles.Secret{
				itinFindingWithLikelihood([]byte("900651234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "starts_with_9",
			in:   []byte("itin: 999-99-9999"),
			want: []veles.Secret{
				itinFindingWithLikelihood([]byte("999-99-9999"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "zeros_allowed_outside_required_prefix",
			in:   []byte("itin: 900-70-0000"),
			want: []veles.Secret{
				itinFindingWithLikelihood([]byte("900-70-0000"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "lower_range_min",
			in:   []byte("itin: 900-50-1234"),
			want: []veles.Secret{
				itinFindingWithLikelihood([]byte("900-50-1234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "lower_range_max",
			in:   []byte("itin: 900-65-1234"),
			want: []veles.Secret{
				itinFindingWithLikelihood([]byte("900-65-1234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "upper_range_min",
			in:   []byte("itin: 900-70-1234"),
			want: []veles.Secret{
				itinFindingWithLikelihood([]byte("900-70-1234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "upper_range_before_89",
			in:   []byte("itin: 900-88-1234"),
			want: []veles.Secret{
				itinFindingWithLikelihood([]byte("900-88-1234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "upper_range_after_89",
			in:   []byte("itin: 900-90-1234"),
			want: []veles.Secret{
				itinFindingWithLikelihood([]byte("900-90-1234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "upper_range_before_93",
			in:   []byte("itin: 900-92-1234"),
			want: []veles.Secret{
				itinFindingWithLikelihood([]byte("900-92-1234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "upper_range_after_93",
			in:   []byte("itin: 900-94-1234"),
			want: []veles.Secret{
				itinFindingWithLikelihood([]byte("900-94-1234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "upper_range_max",
			in:   []byte("itin: 900-99-1234"),
			want: []veles.Secret{
				itinFindingWithLikelihood([]byte("900-99-1234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "form_keyword",
			in:   []byte("form w-7 applicant id: 900-70-4567"),
			want: []veles.Secret{
				itinFindingWithLikelihood([]byte("900-70-4567"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "multiple_matches",
			in:   []byte("900-70-1234 900501234 900-99-9999"),
			want: []veles.Secret{
				itinFinding([]byte("900-70-1234")),
				itinFinding([]byte("900501234")),
				itinFinding([]byte("900-99-9999")),
			},
		},
		{
			name: "multiple_matches_long_gap",
			in:   []byte("900-70-1234" + strings.Repeat(" ", 50000) + "900501234"),
			want: []veles.Secret{
				itinFinding([]byte("900-70-1234")),
				itinFinding([]byte("900501234")),
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

func TestDetect_keywordMatches(t *testing.T) {
	e, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		in   []byte
	}{
		{
			name: "itin",
			in:   []byte("itin: 900-70-1234"),
		},
		{
			name: "individual_taxpayer_identification_number",
			in:   []byte("individual taxpayer identification number: 900-70-1234"),
		},
		{
			name: "individual_taxpayer_identification",
			in:   []byte("individual taxpayer identification: 900-70-1234"),
		},
		{
			name: "individual_tax_identification_number",
			in:   []byte("individual tax identification number: 900-70-1234"),
		},
		{
			name: "individual_tax_id",
			in:   []byte("individual tax id: 900-70-1234"),
		},
		{
			name: "individual_taxpayer_id",
			in:   []byte("individual taxpayer id: 900-70-1234"),
		},
		{
			name: "individual_tin",
			in:   []byte("individual tin: 900-70-1234"),
		},
		{
			name: "irs_itin",
			in:   []byte("irs itin: 900-70-1234"),
		},
		{
			name: "form_w_7",
			in:   []byte("form w-7: 900-70-1234"),
		},
		{
			name: "w_7",
			in:   []byte("w-7: 900-70-1234"),
		},
		{
			name: "case_insensitive",
			in:   []byte("IRS ITIN: 900-70-1234"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, derr := e.Detect(t.Context(), bytes.NewBuffer(tc.in))
			if derr != nil {
				t.Fatal(derr)
			}
			want := []veles.Secret{
				itinFindingWithLikelihood([]byte("900-70-1234"), sensitiveinformation.LikelihoodLikely),
			}
			if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
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
			in:   []byte("not an itin"),
		},
		{
			name: "does_not_start_with_9",
			in:   []byte("800-70-1234"),
		},
		{
			name: "unformatted_does_not_start_with_9",
			in:   []byte("800701234"),
		},
		{
			name: "fourth_and_fifth_digits_below_range",
			in:   []byte("900-49-1234"),
		},
		{
			name: "unformatted_fourth_and_fifth_digits_below_range",
			in:   []byte("900491234"),
		},
		{
			name: "fourth_and_fifth_digits_between_ranges",
			in:   []byte("900-66-1234"),
		},
		{
			name: "unformatted_fourth_and_fifth_digits_between_ranges",
			in:   []byte("900661234"),
		},
		{
			name: "fourth_and_fifth_digits_before_upper_range",
			in:   []byte("900-69-1234"),
		},
		{
			name: "unformatted_fourth_and_fifth_digits_before_upper_range",
			in:   []byte("900691234"),
		},
		{
			name: "fourth_and_fifth_digits_excluded_89",
			in:   []byte("900-89-1234"),
		},
		{
			name: "unformatted_fourth_and_fifth_digits_excluded_89",
			in:   []byte("900891234"),
		},
		{
			name: "fourth_and_fifth_digits_excluded_93",
			in:   []byte("900-93-1234"),
		},
		{
			name: "unformatted_fourth_and_fifth_digits_excluded_93",
			in:   []byte("900931234"),
		},
		{
			name: "missing_digit",
			in:   []byte("900-70-123"),
		},
		{
			name: "unformatted_missing_digit",
			in:   []byte("90070123"),
		},
		{
			name: "extra_digit",
			in:   []byte("900-70-12345"),
		},
		{
			name: "unformatted_extra_digit",
			in:   []byte("9007012345"),
		},
		{
			name: "mixed_separators",
			in:   []byte("900 70-1234"),
		},
		{
			name: "spaced",
			in:   []byte("900 70 1234"),
		},
		{
			name: "within_longer_string",
			in:   []byte("asdf900-70-1234asdf"),
		},
		{
			name: "unformatted_within_longer_string",
			in:   []byte("asdf900701234asdf"),
		},
		{
			name: "ssn_shaped_number",
			in:   []byte("123-45-6789"),
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
	if got, want := NewDetector().MaxSecretLen(), uint32(len("900-70-1234")+(2*contextWindowSize)); got != want {
		t.Errorf("MaxSecretLen() = %d, want %d", got, want)
	}
}

func itinFinding(raw []byte) sensitiveinformation.SensitiveInformation {
	return itinFindingWithLikelihood(raw, sensitiveinformation.LikelihoodUnlikely)
}

func itinFindingWithLikelihood(raw []byte, likelihood sensitiveinformation.Likelihood) sensitiveinformation.SensitiveInformation {
	return sensitiveinformation.SensitiveInformation{
		InfoType: sensitiveinformation.InfoType{
			Name:        "INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER",
			Sensitivity: sensitiveinformation.SensitivityLevelHigh,
		},
		Likelihood: likelihood,
		Raw:        raw,
	}
}
