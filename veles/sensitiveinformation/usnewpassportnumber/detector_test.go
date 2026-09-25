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

package usnewpassportnumber

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	validUSPassportNumber = "A12345678"
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		NewDetector(),
		validUSPassportNumber,
		buildExpectedResult([]byte(validUSPassportNumber), sensitiveinformation.LikelihoodUnlikely),
	)
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
			name:  "number_with_keyword",
			input: `passport_number: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "number_with_keyword_lowercase",
			input: `passport_number: a12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("a12345678"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name: "log_json_pretty",
			input: `{
		  "level": "INFO",
		  "user_id": "1234",
		  "document_number": "A12345000"
		  "passport_number": "A12345678"
		}
		`,
			want: []veles.Secret{
				buildExpectedResult([]byte("A12345000"), sensitiveinformation.LikelihoodLikely),
				buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name:  "log_json_minified",
			input: `{"level":"INFO","user_id":"1234","passport_number":"A12345678"}`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_after",
			input: `A12345678 passport number`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "passport_number_spaced",
			input: `passport number: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "passport_no",
			input: `passport no: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "passport_num",
			input: `passport num: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "passport_hash",
			input: `passport #: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "travel_document_number",
			input: `travel document number: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "travel_doc_no",
			input: `travel doc no: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "passport_book_number",
			input: `passport book number: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodLikely)},
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
			name:  "us_passport_left",
			input: `us passport: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_passport_right",
			input: `passport us: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "usa_passport_left",
			input: `usa passport: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "usa_passport_right",
			input: `passport usa: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "united_states_passport_left",
			input: `united states passport: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "united_states_passport_right",
			input: `passport united states: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "american_passport_left",
			input: `american passport: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "american_passport_right",
			input: `passport american: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_passport_number_left",
			input: `us passport number: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_passport_number_right",
			input: `passport number us: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_passport_no_left",
			input: `us passport no: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_passport_no_right",
			input: `passport no us: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_pass_no_left",
			input: `us pass no: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_pass_no_right",
			input: `pass no us: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_passport_hash_left",
			input: `us passport #: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_passport_hash_right",
			input: `passport us #: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_travel_document_left",
			input: `us travel document: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_travel_document_right",
			input: `travel document us: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_travel_doc_left",
			input: `us travel doc: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_travel_doc_right",
			input: `travel doc us: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "united_states_travel_document_left",
			input: `united states travel document: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "united_states_travel_document_right",
			input: `travel document united states: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "case_insensitive_left",
			input: `US PASSPORT: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "case_insensitive_right",
			input: `PASSPORT US: A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
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
			name:  "number_alone",
			input: `A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "number_with_unrelated_text",
			input: `some random text A12345678 more random text`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name: "number_in_unrelated_list",
			input: `user_id,value
    123,A12345678
    `,
			want: []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodUnlikely)},
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
			name:  "invalid_number_missing_letter",
			input: `12345678`,
		},
		{
			name:  "invalid_number_missing_number",
			input: `A1234567`,
		},
		{
			name:  "invalid_number_dash_separator",
			input: `A_12345678`,
		},
		{
			name:  "invalid_number_space_separator",
			input: `A 12345678`,
		},
		{
			name:  "numeric_first_character",
			input: `123456789`,
		},
		{
			name:  "text_without_number",
			input: `not a passport number`,
		},
		{
			name:  "invalid_number_too_long",
			input: `A123456789`,
		},
		{
			name:  "invalid_second_character_alpha",
			input: `AB2345678`,
		},
		{
			name:  "invalid_number_dash_middle",
			input: `A1234-678`,
		},
		{
			name:  "invalid_number_space_middle",
			input: `A1234 678`,
		},
		{
			name:  "number_within_longer_string",
			input: `asdfA12345678asdf`,
		},
		{
			name:  "number_within_underscores",
			input: `asdf_A12345678_asdf`,
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

func TestDetector_OutsideSearchWindow(t *testing.T) {
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
			name: "long_log_csv",
			input: `user_id,passport_number
		000,000
		000,000
		000,000
		000,000
		123,A12345678
		`,
			want: []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodUnlikely)},
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

func buildExpectedResult(blob []byte, likelihood sensitiveinformation.Likelihood) sensitiveinformation.SensitiveInformation {
	return sensitiveinformation.SensitiveInformation{
		InfoType: sensitiveinformation.InfoType{
			Name:        "US_PASSPORT_NUMBER",
			Sensitivity: sensitiveinformation.SensitivityLevelHigh,
		},
		Likelihood: likelihood,
		Raw:        blob,
	}
}
