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
			name: "match_only",
			in:   []byte("5100000000000008"),
			want: []veles.Secret{
				creditCardFindingWithLikelihood([]byte("5100000000000008"), sensitiveinformation.LikelihoodUnlikely),
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
			name: "keyword_before_increases_likelihood",
			in:   []byte("credit card: 5100000000000008"),
			want: []veles.Secret{
				creditCardFinding([]byte("5100000000000008")),
			},
		},
		{
			name: "keyword_after_increases_likelihood",
			in:   []byte("5100000000000008 card holder"),
			want: []veles.Secret{
				creditCardFinding([]byte("5100000000000008")),
			},
		},
		{
			name: "case_insensitive_keyword_increases_likelihood",
			in:   []byte("VISA 5100000000000008"),
			want: []veles.Secret{
				creditCardFinding([]byte("5100000000000008")),
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
			in:   []byte("510000000000"),
		},
		{
			name: "too_long",
			in:   []byte("51000000000000000000"),
		},
		{
			name: "bad_checksum",
			in:   []byte("5100000000000007"),
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

func TestDetectorMaxSecretLen(t *testing.T) {
	if got, want := NewDetector().MaxSecretLen(), uint32(len("5100 0000 0000 0000 008")+(2*contextWindowSize)); got != want {
		t.Errorf("MaxSecretLen() = %d, want %d", got, want)
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
