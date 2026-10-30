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

package creditcard

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

const testCreditCard = "5100 0000 0000 0008"

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		NewDetector(),
		testCreditCard,
		creditCardFindingWithLikelihood([]byte(testCreditCard), sensitiveinformation.LikelihoodUnlikely),
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
			name: "bad_checksum_stays_low_confidence",
			in:   []byte("5100000000000007"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("5100000000000007"), sensitiveinformation.LikelihoodUnlikely),
			},
		},
		{
			name: "bad_checksum_with_keyword_and_issuer_stays_low_confidence",
			in:   []byte("credit card: 5100-0000-0000-0007"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("5100-0000-0000-0007"), sensitiveinformation.LikelihoodUnlikely),
			},
		},
		{
			name: "bad_checksum_with_keyword_without_known_issuer_stays_low_confidence",
			in:   []byte("credit card: 7000000000000000046"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("7000000000000000046"), sensitiveinformation.LikelihoodUnlikely),
			},
		},
		{
			name: "match_only",
			in:   []byte("5100000000000008"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("5100000000000008"), sensitiveinformation.LikelihoodUnlikely),
			},
		},
		{
			name: "match_12_digits_low_confidence",
			in:   []byte("700000000005"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("700000000005"), sensitiveinformation.LikelihoodUnlikely),
			},
		},
		{
			name: "match_spaced",
			in:   []byte("2221 0000 0000 0009"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("2221 0000 0000 0009"), sensitiveinformation.LikelihoodUnlikely),
			},
		},
		{
			name: "match_hyphenated",
			in:   []byte("5100-0000-0000-0008."),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("5100-0000-0000-0008"), sensitiveinformation.LikelihoodUnlikely),
			},
		},
		{
			name: "match_15_digits",
			in:   []byte("340000000000009"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("340000000000009"), sensitiveinformation.LikelihoodUnlikely),
			},
		},
		{
			name: "keyword_before_mid_confidence",
			in:   []byte("credit card: 700000000005"),
			want: []veles.Secret{
				creditCardFinding([]byte("700000000005")),
			},
		},
		{
			name: "keyword_after_high_confidence",
			in:   []byte("5100000000000008 card holder"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("5100000000000008"), sensitiveinformation.LikelihoodVeryLikely),
			},
		},
		{
			name: "case_insensitive_keyword_high_confidence",
			in:   []byte("VISA 5100000000000008"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("5100000000000008"), sensitiveinformation.LikelihoodVeryLikely),
			},
		},
		{
			name: "common_issuer_without_keyword_stays_low_confidence",
			in:   []byte("4000000000000002"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("4000000000000002"), sensitiveinformation.LikelihoodUnlikely),
			},
		},
		{
			name: "common_issuer_with_keyword_high_confidence",
			in:   []byte("credit card: 4000000000000002"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("4000000000000002"), sensitiveinformation.LikelihoodVeryLikely),
			},
		},
		{
			name: "credit_card_keyword_high_confidence",
			in:   []byte("credit_card: 4000000000000002"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("4000000000000002"), sensitiveinformation.LikelihoodVeryLikely),
			},
		},
		{
			name: "credit_card_hyphenated_keyword_high_confidence",
			in:   []byte("credit-card: 4000000000000002"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("4000000000000002"), sensitiveinformation.LikelihoodVeryLikely),
			},
		},
		{
			name: "card_holder_keyword_high_confidence",
			in:   []byte("card_holder: 4000000000000002"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("4000000000000002"), sensitiveinformation.LikelihoodVeryLikely),
			},
		},
		{
			name: "card_holder_hyphenated_keyword_high_confidence",
			in:   []byte("card-holder: 4000000000000002"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("4000000000000002"), sensitiveinformation.LikelihoodVeryLikely),
			},
		},
		{
			name: "keyword_outside_context_window_keeps_unlikely_likelihood",
			in:   []byte("credit card" + strings.Repeat(" ", contextWindowSize+1) + "5100000000000008"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("5100000000000008"), sensitiveinformation.LikelihoodUnlikely),
			},
		},
		{
			name: "multiple_matches",
			in:   []byte("5100000000000008 2221000000000009"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("5100000000000008"), sensitiveinformation.LikelihoodUnlikely),
				creditCardFindingWithLikelihood([]byte("2221000000000009"), sensitiveinformation.LikelihoodUnlikely),
			},
		},
		{
			name: "multiple_matches_long_gap",
			in:   []byte("5100000000000008" + strings.Repeat(" ", 50000) + "2221000000000009"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("5100000000000008"), sensitiveinformation.LikelihoodUnlikely),
				creditCardFindingWithLikelihood([]byte("2221000000000009"), sensitiveinformation.LikelihoodUnlikely),
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
			in:   []byte("not a credit card"),
		},
		{
			name: "too_short",
			in:   []byte("70000000000"),
		},
		{
			name: "too_long",
			in:   []byte("51000000000000000000"),
		},
		{
			name: "all_same_digits",
			in:   []byte("0000000000000000"),
		},
		{
			name: "within_longer_string",
			in:   []byte("asdf5100000000000008asdf"),
		},
		{
			name: "placeholder_visa",
			in:   []byte("4111 1111 1111 1111"),
		},
		{
			name: "placeholder_mastercard",
			in:   []byte("5555-5555-5555-4444"),
		},
		{
			name: "placeholder_amex",
			in:   []byte("378282246310005"),
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

func TestDetect_published_test_cards(t *testing.T) {
	e, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	for number := range commonExamples {
		t.Run(number, func(t *testing.T) {
			for _, separator := range []string{"", " ", "-"} {
				var groups []string
				for i := 0; i < len(number); i += 4 {
					groups = append(groups, number[i:min(i+4, len(number))])
				}
				input := "credit card: " + strings.Join(groups, separator)
				got, err := e.Detect(t.Context(), strings.NewReader(input))
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != 0 {
					t.Errorf("Detect(%q) returned %d findings, want none", input, len(got))
				}
			}
		})
	}
}

func TestValidCreditCardNumber(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{name: "minimum_12_digits", in: "700000000047", want: true},
		{name: "even_length_doubled_4", in: "7000000000000047", want: true},
		{name: "even_length_doubled_5", in: "7000000000000054", want: true},
		{name: "even_length_doubled_9", in: "7000000000000096", want: true},
		{name: "odd_length_doubled_4", in: "7000000000000000045", want: true},
		{name: "odd_length_doubled_5", in: "7000000000000000052", want: true},
		{name: "odd_length_doubled_9", in: "7000000000000000094", want: true},
		{name: "even_length_bad_checksum_is_not_filtered", in: "7000000000000048", want: true},
		{name: "odd_length_bad_checksum_is_not_filtered", in: "7000000000000000046", want: true},
		{name: "spaced", in: "7000 0000 0000 0047", want: true},
		{name: "hyphenated", in: "7000-0000-0000-0047", want: true},
		{name: "empty"},
		// These fail length validation despite passing Luhn.
		{name: "too_short", in: "70000000003"},
		{name: "too_long", in: "70000000000000000005"},
		{name: "letter", in: "7000000000000047a"},
		{name: "unsupported_punctuation", in: "7000/0000/0000/0047"},
		{name: "all_zeroes", in: "0000000000000000"},
		{name: "all_sixes", in: "6666666666666666"},
		{name: "published_test_card", in: "4242424242424242"},
		{name: "published_test_card_spaced", in: "4242 4242 4242 4242"},
		{name: "published_test_card_hyphenated", in: "4242-4242-4242-4242"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validCreditCardNumber([]byte(tc.in)); got != tc.want {
				t.Errorf("validCreditCardNumber(%q) = %t, want %t", tc.in, got, tc.want)
			}
		})
	}
}

func TestLuhnCheck(t *testing.T) {
	// The penultimate digit is always doubled: 4 becomes 8, 5 becomes 1,
	// and 9 becomes 9 after reduction. Nonzero check digits stay unchanged.
	cases := []struct {
		name   string
		digits string
		want   bool
	}{
		{name: "minimum_12_digits", digits: "700000000047", want: true},
		{name: "even_length_doubled_4", digits: "7000000000000047", want: true},
		{name: "even_length_doubled_5", digits: "7000000000000054", want: true},
		{name: "even_length_doubled_9", digits: "7000000000000096", want: true},
		{name: "odd_length_doubled_4", digits: "7000000000000000045", want: true},
		{name: "odd_length_doubled_5", digits: "7000000000000000052", want: true},
		{name: "odd_length_doubled_9", digits: "7000000000000000094", want: true},
		{name: "even_length_bad_checksum", digits: "7000000000000048"},
		{name: "odd_length_bad_checksum", digits: "7000000000000000046"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := luhnCheck(tc.digits); got != tc.want {
				t.Errorf("luhnCheck(%q) = %t, want %t", tc.digits, got, tc.want)
			}
		})
	}
}

func TestDetectorMaxSecretLen(t *testing.T) {
	if got, want := NewDetector().MaxSecretLen(), uint32(len("5100 0000 0000 0000 008")+(2*contextWindowSize)); got != want {
		t.Errorf("MaxSecretLen() = %d, want %d", got, want)
	}
}

func TestHasCommonIssuerAndLength(t *testing.T) {
	cases := []struct {
		name   string
		digits string
		want   bool
	}{
		{
			name:   "visa_13_digits",
			digits: "4000000000000",
			want:   true,
		},
		{
			name:   "visa_16_digits",
			digits: "4000000000000002",
			want:   true,
		},
		{
			name:   "visa_19_digits",
			digits: "4000000000000000002",
			want:   true,
		},
		{
			name:   "visa_wrong_length",
			digits: "400000000000",
			want:   false,
		},
		{
			name:   "mastercard_51_to_55_range",
			digits: "5100000000000008",
			want:   true,
		},
		{
			name:   "mastercard_2221_to_2720_range_lower_bound",
			digits: "2221000000000009",
			want:   true,
		},
		{
			name:   "mastercard_2221_to_2720_range_upper_bound",
			digits: "2720000000000008",
			want:   true,
		},
		{
			name:   "mastercard_wrong_length",
			digits: "510000000000000",
			want:   false,
		},
		{
			name:   "amex_34_prefix",
			digits: "340000000000009",
			want:   true,
		},
		{
			name:   "amex_37_prefix",
			digits: "370000000000002",
			want:   true,
		},
		{
			name:   "amex_wrong_length",
			digits: "3400000000000000",
			want:   false,
		},
		{
			name:   "discover_6011_prefix",
			digits: "6011000000000004",
			want:   true,
		},
		{
			name:   "discover_644_to_649_range",
			digits: "6440000000000006",
			want:   true,
		},
		{
			name:   "discover_65_prefix",
			digits: "6500000000000002",
			want:   true,
		},
		{
			name:   "discover_622126_to_622925_range_lower_bound",
			digits: "6221260000000000",
			want:   true,
		},
		{
			name:   "discover_622126_to_622925_range_upper_bound",
			digits: "6229250000000007",
			want:   true,
		},
		{
			name:   "discover_19_digits",
			digits: "6011000000000000004",
			want:   true,
		},
		{
			name:   "discover_wrong_length",
			digits: "601100000000000",
			want:   false,
		},
		{
			name:   "jcb_3528_to_3589_range_lower_bound",
			digits: "3528000000000007",
			want:   true,
		},
		{
			name:   "jcb_3528_to_3589_range_upper_bound",
			digits: "3589000000000003",
			want:   true,
		},
		{
			name:   "jcb_19_digits",
			digits: "3528000000000000007",
			want:   true,
		},
		{
			name:   "jcb_wrong_length",
			digits: "352800000000000",
			want:   false,
		},
		{
			name:   "diners_club_300_to_305_range",
			digits: "30000000000004",
			want:   true,
		},
		{
			name:   "diners_club_36_prefix",
			digits: "36000000000008",
			want:   true,
		},
		{
			name:   "diners_club_38_to_39_range",
			digits: "38000000000006",
			want:   true,
		},
		{
			name:   "diners_club_19_digits",
			digits: "3000000000000000004",
			want:   true,
		},
		{
			name:   "diners_club_wrong_length",
			digits: "3000000000000",
			want:   false,
		},
		{
			name:   "unionpay_62_prefix",
			digits: "6200000000000005",
			want:   true,
		},
		{
			name:   "t_union_31_prefix_19_digits",
			digits: "3100000000000000008",
			want:   true,
		},
		{
			name:   "maestro_12_digits",
			digits: "501800000003",
			want:   true,
		},
		{
			name:   "mir_2200_to_2204_range",
			digits: "2200000000000004",
			want:   true,
		},
		{
			name:   "rupay_81_prefix",
			digits: "8100000000000007",
			want:   true,
		},
		{
			name:   "verve_18_digits",
			digits: "506099000000000004",
			want:   true,
		},
		{
			name:   "uatp_1_prefix_15_digits",
			digits: "100000000000008",
			want:   true,
		},
		{
			name:   "gpn_60_to_63_range",
			digits: "6300000000000001",
			want:   true,
		},
		{
			name:   "unknown_issuer",
			digits: "7000000000000005",
			want:   false,
		},
		{
			name:   "too_short_for_prefix",
			digits: "6",
			want:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasCommonIssuerAndLength(tc.digits); got != tc.want {
				t.Errorf("hasCommonIssuerAndLength(%q) = %t, want %t", tc.digits, got, tc.want)
			}
		})
	}
}

// TestIssuerRangesWellFormed guards the invariant that prefixInRange relies on:
// lowIIN and highIIN must have the same number of digits, and lowIIN <= highIIN.
func TestIssuerRangesWellFormed(t *testing.T) {
	for i, r := range issuerRanges {
		if r.lowIIN > r.highIIN {
			t.Errorf("issuerRanges[%d]: lowIIN %s > highIIN %s", i, r.lowIIN, r.highIIN)
		}
		if lo, hi := len(r.lowIIN), len(r.highIIN); lo != hi {
			t.Errorf("issuerRanges[%d]: lowIIN %s (%d digits) and highIIN %s (%d digits) must have the same number of digits", i, r.lowIIN, lo, r.highIIN, hi)
		}
		if len(r.lengths) == 0 {
			t.Errorf("issuerRanges[%d]: lengths must not be empty", i)
		}
	}
}

func creditCardFinding(raw []byte) sensitiveinformation.SensitiveInformation {
	return creditCardFindingWithLikelihood(raw, sensitiveinformation.LikelihoodLikely)
}

func creditCardFindingWithLikelihood(raw []byte, likelihood sensitiveinformation.Likelihood) sensitiveinformation.SensitiveInformation {
	return sensitiveinformation.SensitiveInformation{
		InfoType: sensitiveinformation.InfoType{
			Name:        "CREDIT_CARD_NUMBER",
			Sensitivity: sensitiveinformation.SensitivityLevelHigh,
		},
		Likelihood: likelihood,
		Raw:        raw,
	}
}
