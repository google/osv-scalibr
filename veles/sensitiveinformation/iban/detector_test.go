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

package iban

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

const testIBAN = "GB44 BARC 2003 0571 1187 42"

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		NewDetector(),
		testIBAN,
		ibanFinding([]byte(testIBAN)),
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
			in:   []byte("GB44BARC20030571118742"),
			want: []veles.Secret{
				ibanFinding([]byte("GB44BARC20030571118742")),
			},
		},
		{
			name: "match_spaced",
			in:   []byte("FR76 3000 6000 0112 3456 7890 189"),
			want: []veles.Secret{
				ibanFinding([]byte("FR76 3000 6000 0112 3456 7890 189")),
			},
		},
		{
			name: "match_another_spaced",
			in:   []byte("PL21 1240 4533 1111 0000 5428 2421"),
			want: []veles.Secret{
				ibanFinding([]byte("PL21 1240 4533 1111 0000 5428 2421")),
			},
		},
		{
			name: "match_in_text",
			in:   []byte("iban: FR7630006000011234567890189."),
			want: []veles.Secret{
				ibanFinding([]byte("FR7630006000011234567890189")),
			},
		},
		{
			name: "lowercase",
			in:   []byte("gb44barc20030571118742"),
			want: []veles.Secret{
				ibanFinding([]byte("gb44barc20030571118742")),
			},
		},
		{
			name: "multiple_matches",
			in:   []byte("first: PL21 1240 4533 1111 0000 5428 2421 second: PL10 1090 1753 0000 0001 5913 2875"),
			want: []veles.Secret{
				ibanFinding([]byte("PL21 1240 4533 1111 0000 5428 2421")),
				ibanFinding([]byte("PL10 1090 1753 0000 0001 5913 2875")),
			},
		},
		{
			name: "multiple_matches_long_gap",
			in:   []byte("GB44BARC20030571118742" + strings.Repeat(" ", 50000) + "FR76 3000 6000 0112 3456 7890 189"),
			want: []veles.Secret{
				ibanFinding([]byte("GB44BARC20030571118742")),
				ibanFinding([]byte("FR76 3000 6000 0112 3456 7890 189")),
			},
		},
		{
			name: "minimum_length_country",
			in:   []byte("NO66 8601 1117 948"),
			want: []veles.Secret{
				ibanFinding([]byte("NO66 8601 1117 948")),
			},
		},
		{
			name: "maximum_length_country",
			in:   []byte("RU13 0445 2599 9000 0000 0000 0000 0000 0"),
			want: []veles.Secret{
				ibanFinding([]byte("RU13 0445 2599 9000 0000 0000 0000 0000 0")),
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
			in:   []byte("not an iban"),
		},
		{
			name: "bad_checksum",
			in:   []byte("GB45BARC20030571118742"),
		},
		{
			name: "bad_country_length",
			in:   []byte("GB44BARC200305711187421"),
		},
		{
			name: "compact_too_short",
			in:   []byte("NO938601111794"),
		},
		{
			name: "compact_too_long",
			in:   []byte("RU13044525999000000000000000000000"),
		},
		{
			name: "unknown_country",
			in:   []byte("ZZ64BARC20030571118742"),
		},
		{
			name: "missing_country_code",
			in:   []byte("44124045331111000054282421"),
		},
		{
			name: "missing_check_digits",
			in:   []byte("PLAA124045331111000054282421"),
		},
		{
			name: "hyphenated",
			in:   []byte("GB44-BARC-2003-0571-1187-42"),
		},
		{
			name: "mixed_separator_groups",
			in:   []byte("GB44 BARC2003 0571 1187 42"),
		},
		{
			name: "short_middle_group",
			in:   []byte("PL21 1240 453 1111 0000 5428 2421"),
		},
		{
			name: "long_final_group",
			in:   []byte("PL21 1240 4533 1111 0000 5428 24210"),
		},
		{
			name: "within_longer_string",
			in:   []byte("asdfGB44BARC20030571118742asdf"),
		},
		{
			name: "spaced_within_longer_string",
			in:   []byte("asdf PL21 1240 4533 1111 0000 5428 2421asdf"),
		},
		{
			name: "common_example_gb",
			in:   []byte("GB82 WEST 1234 5698 7654 32"),
		},
		{
			name: "common_example_de",
			in:   []byte("DE89 3704 0044 0532 0130 00"),
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
	if got, want := NewDetector().MaxSecretLen(), uint32(len("RU13 0445 2599 9000 0000 0000 0000 0000 0")); got != want {
		t.Errorf("MaxSecretLen() = %d, want %d", got, want)
	}
}

func ibanFinding(raw []byte) sensitiveinformation.SensitiveInformation {
	return sensitiveinformation.SensitiveInformation{
		InfoType: sensitiveinformation.InfoType{
			Name:        "International Bank Account Number",
			Sensitivity: sensitiveinformation.SensitivityLevelLow,
		},
		Likelihood: sensitiveinformation.LikelihoodVeryLikely,
		Raw:        raw,
	}
}
