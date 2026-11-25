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

package abartn

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	validRtnNumber = "000000510"
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		NewDetector(),
		validRtnNumber,
		buildExpectedResult([]byte(validRtnNumber), sensitiveinformation.LikelihoodUnlikely),
	)
}

func TestDetector_Unlikely(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "invalid_checksum_prefix_00",
			input: `000000510`,
			want:  []veles.Secret{buildExpectedResult([]byte("000000510"), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "invalid_checksum_prefix_01",
			input: `011000010`,
			want:  []veles.Secret{buildExpectedResult([]byte("011000010"), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "invalid_checksum_prefix_12",
			input: `121000240`,
			want:  []veles.Secret{buildExpectedResult([]byte("121000240"), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "invalid_checksum_prefix_21",
			input: `211070170`,
			want:  []veles.Secret{buildExpectedResult([]byte("211070170"), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "invalid_checksum_prefix_32",
			input: `322271620`,
			want:  []veles.Secret{buildExpectedResult([]byte("322271620"), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "invalid_checksum_prefix_61",
			input: `611000000`,
			want:  []veles.Secret{buildExpectedResult([]byte("611000000"), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "invalid_checksum_prefix_72",
			input: `721000000`,
			want:  []veles.Secret{buildExpectedResult([]byte("721000000"), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "invalid_checksum_prefix_80",
			input: `800000000`,
			want:  []veles.Secret{buildExpectedResult([]byte("800000000"), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "invalid_checksum_single_digit_error",
			input: `021000022`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000022"), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "invalid_checksum_transposed_digits",
			input: `012000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("012000021"), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "invalid_checksum_with_dashes",
			input: `0210-0002-2`,
			want:  []veles.Secret{buildExpectedResult([]byte("0210-0002-2"), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "invalid_checksum_multiple_rtns",
			input: `021000022 121000240`,
			want: []veles.Secret{
				buildExpectedResult([]byte("021000022"), sensitiveinformation.LikelihoodUnlikely),
				buildExpectedResult([]byte("121000240"), sensitiveinformation.LikelihoodUnlikely),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetector_Likely(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "rtn_prefix_00",
			input: `000000518`,
			want:  []veles.Secret{buildExpectedResult([]byte("000000518"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "rtn_prefix_01",
			input: `011000015`,
			want:  []veles.Secret{buildExpectedResult([]byte("011000015"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "rtn_prefix_12",
			input: `121000248`,
			want:  []veles.Secret{buildExpectedResult([]byte("121000248"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "rtn_prefix_21",
			input: `211070175`,
			want:  []veles.Secret{buildExpectedResult([]byte("211070175"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "rtn_prefix_32",
			input: `322271627`,
			want:  []veles.Secret{buildExpectedResult([]byte("322271627"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "rtn_prefix_61",
			input: `611000004`,
			want:  []veles.Secret{buildExpectedResult([]byte("611000004"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "rtn_prefix_72",
			input: `721000004`,
			want:  []veles.Secret{buildExpectedResult([]byte("721000004"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "rtn_prefix_80",
			input: `800000006`,
			want:  []veles.Secret{buildExpectedResult([]byte("800000006"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "valid_checksum_wikipedia_example",
			input: `111000025`,
			want:  []veles.Secret{buildExpectedResult([]byte("111000025"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "rtn_with_dashes",
			input: `0210-0002-1`,
			want:  []veles.Secret{buildExpectedResult([]byte("0210-0002-1"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "multiple_rtns",
			input: `021000021 121000248`,
			want: []veles.Secret{
				buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodLikely),
				buildExpectedResult([]byte("121000248"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name:  "keyword_invalid_checksum",
			input: `ABA: 021000022`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000022"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_invalid_checksum_with_dashes",
			input: `ABA: 0210-0002-2`,
			want:  []veles.Secret{buildExpectedResult([]byte("0210-0002-2"), sensitiveinformation.LikelihoodLikely)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetector_VeryLikely(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "keyword_aba_before",
			input: `ABA: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_aba_after",
			input: `021000021 ABA`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_aba_lowercase",
			input: `aba: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_aba_number",
			input: `ABA number: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_aba_underscore",
			input: `aba_routing_number=021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_abartn",
			input: `abartn: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_aba_camelcase",
			input: `bankAba: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_aba_camelcase_uppercase",
			input: `bankABA: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_aba_camelcase_number",
			input: `abaNumber: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_aba_snakecase_middle",
			input: `bank_aba_number=021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_aba_snakecase_uppercase",
			input: `BANK_ABA_NUMBER=021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_aba_json_key",
			input: `{"aba": "021000021"}`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_aba_parentheses",
			input: `(ABA) 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_rtn_snakecase",
			input: `bank_rtn=021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_rtn_camelcase",
			input: `customerRtn: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_rtn_camelcase_uppercase",
			input: `bankRTN: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_rtn_camelcase_number",
			input: `rtnNumber: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_rtn_snakecase_middle",
			input: `bank_rtn_number=021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_rtn_snakecase_uppercase",
			input: `BANK_RTN_NUMBER=021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_rtn_json_key",
			input: `{"rtn": "021000021"}`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_rtn_parentheses",
			input: `(RTN) 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_micr_before",
			input: `MICR: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_micr_after",
			input: `021000021 MICR`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_micr_lowercase",
			input: `micr: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_micr_line",
			input: `MICR line: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_micr_snakecase",
			input: `micr_line=021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_micr_camelcase",
			input: `checkMicr: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_micr_camelcase_line",
			input: `micrLine: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_micr_snakecase_middle",
			input: `check_micr_line=021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_micr_snakecase_uppercase",
			input: `CHECK_MICR_LINE=021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_micr_json_key",
			input: `{"micr": "021000021"}`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_micr_parentheses",
			input: `(MICR) 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_rtn_before",
			input: `RTN: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_rtn_after",
			input: `021000021 RTN`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_rtn_lowercase",
			input: `rtn: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_routing_number",
			input: `Routing Number: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_routing_after",
			input: `021000021 routing`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_routing_uppercase",
			input: `ROUTING: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_routing_camelcase",
			input: `routingNumber = "021000021"`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_routing_snake_case",
			input: `bank_routing_number=021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_routing_screaming_snake_case",
			input: `BANK_ROUTING_NUMBER=021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_bank_routing_camelcase",
			input: `bankRoutingNumber: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_aba_routing_camelcase",
			input: `abaRoutingNumber: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_routing_json",
			input: `{"routing": "021000021"}`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_transit_number",
			input: `Transit Number: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_transit_camelcase",
			input: `transitNumber: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_transit_snake_case",
			input: `transit_number=021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_transit_after",
			input: `021000021 transit`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_routing_transit_number",
			input: `Routing Transit Number: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_routing_transit_camelcase",
			input: `routingTransitNumber: 021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_routing_transit_snake_case",
			input: `ROUTING_TRANSIT_NUMBER=021000021`,
			want:  []veles.Secret{buildExpectedResult([]byte("021000021"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "keyword_with_dashes",
			input: `ABA: 0210-0002-1`,
			want:  []veles.Secret{buildExpectedResult([]byte("0210-0002-1"), sensitiveinformation.LikelihoodVeryLikely)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetector_NoMatch(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "len_8",
			input: `ABA: 02100002`,
		},
		{
			name:  "len_10",
			input: `ABA: 0210000210`,
		},
		{
			name:  "placeholder_stripe_test",
			input: `ABA: 110000000`,
		},
		{
			name:  "placeholder_stripe_test_with_dashes",
			input: `ABA: 1100-0000-0`,
		},
		{
			name:  "letter_start",
			input: `ABA: a21000021`,
		},
		{
			name:  "letter_middle",
			input: `ABA: 0210a0021`,
		},
		{
			name:  "letter_end",
			input: `ABA: 02100002a`,
		},
		{
			name:  "ssn_dash_format",
			input: `ABA: 021-00-0021`,
		},
		{
			name:  "space_separated",
			input: `ABA: 0210 0002 1`,
		},
		{
			name:  "wrong_dash_groups",
			input: `ABA: 02100-002-1`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if len(got) != 0 {
				t.Errorf("Detect() got %v secrets, want 0", len(got))
			}
		})
	}
}

func TestDetector_PrefixVerification(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	for p := range 100 {
		rtn := fmt.Sprintf("%02d100001", p)
		rtn = fmt.Sprintf(rtn, calculateChecksum(rtn))
		dashed := rtn[:4] + "-" + rtn[4:8] + "-" + rtn[8:]

		for _, input := range []string{rtn, dashed} {
			t.Run(input, func(t *testing.T) {
				got, err := engine.Detect(t.Context(), strings.NewReader(input))
				if err != nil {
					t.Fatalf("Detect() error: %v, want nil", err)
				}
				want := 0
				if validPrefix(p) {
					want = 1
				}
				if len(got) != want {
					t.Errorf("Detect(%q) got %d secrets, want %d", input, len(got), want)
				}
			})
		}
	}
}

func calculateChecksum(s string) string {
	weights := []int{3, 7, 1, 3, 7, 1, 3, 7}
	sum := 0
	for i, c := range s {
		sum += int(c-'0') * weights[i]
	}
	return s + strconv.Itoa((10-sum%10)%10)
}

func validPrefix(p int) bool {
	return (p >= 0 && p <= 12) || (p >= 21 && p <= 32) || (p >= 61 && p <= 72) || p == 80
}

func buildExpectedResult(raw []byte, likelihood sensitiveinformation.Likelihood) sensitiveinformation.SensitiveInformation {
	return sensitiveinformation.SensitiveInformation{
		InfoType: sensitiveinformation.InfoType{
			Name:        "US_BANK_ROUTING_TRANSIT_NUMBER_MICR",
			Sensitivity: sensitiveinformation.SensitivityLevelModerate,
		},
		Likelihood: likelihood,
		Raw:        raw,
	}
}
