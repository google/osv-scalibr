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

package atin

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

const testAtin = "912-93-6789"

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		NewDetector(),
		testAtin,
		atinFinding([]byte(testAtin)),
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
			in:   []byte("912-93-6789"),
			want: []veles.Secret{
				atinFinding([]byte("912-93-6789")),
			},
		},
		{
			name: "match_without_dashes",
			in:   []byte("912936789"),
			want: []veles.Secret{
				atinFinding([]byte("912936789")),
			},
		},
		{
			name: "keyword_before",
			in:   []byte("atin: 932-93-1234"),
			want: []veles.Secret{
				atinFindingWithLikelihood([]byte("932-93-1234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "unformatted_with_keyword",
			in:   []byte("atin: 932931234"),
			want: []veles.Secret{
				atinFindingWithLikelihood([]byte("932931234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "keyword_after",
			in:   []byte("932-93-1234 adoption taxpayer identification number"),
			want: []veles.Secret{
				atinFindingWithLikelihood([]byte("932-93-1234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "unformatted_keyword_after",
			in:   []byte("932931234 adoption taxpayer identification number"),
			want: []veles.Secret{
				atinFindingWithLikelihood([]byte("932931234"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "starts_with_9",
			in:   []byte("atin: 999-93-9999"),
			want: []veles.Secret{
				atinFindingWithLikelihood([]byte("999-93-9999"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "zeros_allowed_outside_required_prefix",
			in:   []byte("atin: 900-93-0000"),
			want: []veles.Secret{
				atinFindingWithLikelihood([]byte("900-93-0000"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "form_keyword",
			in:   []byte("form w-7a applicant id: 923-93-4567"),
			want: []veles.Secret{
				atinFindingWithLikelihood([]byte("923-93-4567"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name: "multiple_matches",
			in:   []byte("912-93-6789 923936789 999-93-9999"),
			want: []veles.Secret{
				atinFinding([]byte("912-93-6789")),
				atinFinding([]byte("923936789")),
				atinFinding([]byte("999-93-9999")),
			},
		},
		{
			name: "multiple_matches_long_gap",
			in:   []byte("912-93-6789" + strings.Repeat(" ", 50000) + "923936789"),
			want: []veles.Secret{
				atinFinding([]byte("912-93-6789")),
				atinFinding([]byte("923936789")),
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
			name: "atin",
			in:   []byte("atin: 912-93-6789"),
		},
		{
			name: "atin_number",
			in:   []byte("atin number: 912-93-6789"),
		},
		{
			name: "atin_num_with_underscore",
			in:   []byte("atin_num: 912-93-6789"),
		},
		{
			name: "atin_no_with_dash",
			in:   []byte("atin-no: 912-93-6789"),
		},
		{
			name: "atin_hash",
			in:   []byte("atin #: 912-93-6789"),
		},
		{
			name: "adoption_taxpayer_identification_number",
			in:   []byte("adoption taxpayer identification number: 912-93-6789"),
		},
		{
			name: "adoption_taxpayer_identification_number_with_dashes",
			in:   []byte("adoption-taxpayer-identification-number: 912-93-6789"),
		},
		{
			name: "adoption_taxpayer_identification_number_with_underscores",
			in:   []byte("adoption_taxpayer_identification_number: 912-93-6789"),
		},
		{
			name: "adoption_taxpayer_identification",
			in:   []byte("adoption taxpayer identification: 912-93-6789"),
		},
		{
			name: "adoption_tax_identification_number",
			in:   []byte("adoption tax identification number: 912-93-6789"),
		},
		{
			name: "adoption_tax_id",
			in:   []byte("adoption tax id: 912-93-6789"),
		},
		{
			name: "adoption_tax_id_with_underscore",
			in:   []byte("adoption_tax_id: 912-93-6789"),
		},
		{
			name: "adoption_taxpayer_id",
			in:   []byte("adoption taxpayer id: 912-93-6789"),
		},
		{
			name: "adoption_taxpayer_id_with_dash",
			in:   []byte("adoption-taxpayer-id: 912-93-6789"),
		},
		{
			name: "adoption_tin",
			in:   []byte("adoption tin: 912-93-6789"),
		},
		{
			name: "adoption_tin_with_underscore",
			in:   []byte("adoption_tin: 912-93-6789"),
		},
		{
			name: "irs_atin",
			in:   []byte("irs atin: 912-93-6789"),
		},
		{
			name: "irs_atin_with_dash",
			in:   []byte("irs-atin: 912-93-6789"),
		},
		{
			name: "form_w_7a",
			in:   []byte("form w-7a: 912-93-6789"),
		},
		{
			name: "form_w_7a_with_underscore",
			in:   []byte("form_w-7a: 912-93-6789"),
		},
		{
			name: "w_7a",
			in:   []byte("w-7a: 912-93-6789"),
		},
		{
			name: "case_insensitive",
			in:   []byte("IRS ATIN: 912-93-6789"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, derr := e.Detect(t.Context(), bytes.NewBuffer(tc.in))
			if derr != nil {
				t.Fatal(derr)
			}
			want := []veles.Secret{
				atinFindingWithLikelihood([]byte("912-93-6789"), sensitiveinformation.LikelihoodLikely),
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
			in:   []byte("not an atin"),
		},
		{
			name: "does_not_start_with_9",
			in:   []byte("812-93-6789"),
		},
		{
			name: "unformatted_does_not_start_with_9",
			in:   []byte("812936789"),
		},
		{
			name: "fourth_and_fifth_digits_not_93",
			in:   []byte("912-94-6789"),
		},
		{
			name: "unformatted_fourth_and_fifth_digits_not_93",
			in:   []byte("912946789"),
		},
		{
			name: "missing_digit",
			in:   []byte("912-93-678"),
		},
		{
			name: "unformatted_missing_digit",
			in:   []byte("91293678"),
		},
		{
			name: "extra_digit",
			in:   []byte("912-93-67890"),
		},
		{
			name: "unformatted_extra_digit",
			in:   []byte("9129367890"),
		},
		{
			name: "mixed_separators",
			in:   []byte("912 93-6789"),
		},
		{
			name: "spaced",
			in:   []byte("912 93 6789"),
		},
		{
			name: "within_longer_string",
			in:   []byte("asdf912-93-6789asdf"),
		},
		{
			name: "unformatted_within_longer_string",
			in:   []byte("asdf912936789asdf"),
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

func atinFinding(raw []byte) sensitiveinformation.SensitiveInformation {
	return atinFindingWithLikelihood(raw, sensitiveinformation.LikelihoodUnlikely)
}

func atinFindingWithLikelihood(raw []byte, likelihood sensitiveinformation.Likelihood) sensitiveinformation.SensitiveInformation {
	return sensitiveinformation.SensitiveInformation{
		InfoType: sensitiveinformation.InfoType{
			Name:        "ADOPTION_TAXPAYER_IDENTIFICATION_NUMBER",
			Sensitivity: sensitiveinformation.SensitivityLevelHigh,
		},
		Likelihood: likelihood,
		Raw:        raw,
	}
}
