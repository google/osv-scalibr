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

package passportnumber

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
	validPassportNumber = "12345678"
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		NewDetector(),
		validPassportNumber,
		buildExpectedResult([]byte(validPassportNumber), "PASSPORT_NUMBER", sensitiveinformation.LikelihoodUnlikely),
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
			input: `passport_number: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "PASSPORT_NUMBER", sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "number_with_keyword_lowercase",
			input: `passport_number: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "PASSPORT_NUMBER", sensitiveinformation.LikelihoodLikely)},
		},
		{
			name: "log_json_pretty",
			input: `{
		  "level": "INFO",
		  "user_id": "1234",
		  "document_number": "12345000"
		  "passport_number": "12345678"
		}
		`,
			want: []veles.Secret{
				buildExpectedResult([]byte("12345000"), "PASSPORT_NUMBER", sensitiveinformation.LikelihoodLikely),
				buildExpectedResult([]byte("12345678"), "PASSPORT_NUMBER", sensitiveinformation.LikelihoodLikely),
			},
		},
		{
			name:  "log_json_minified",
			input: `{"level":"INFO","user_id":"1234","passport_number":"12345678"}`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "PASSPORT_NUMBER", sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_after",
			input: `12345678 passport number`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "PASSPORT_NUMBER", sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "passport_number_spaced",
			input: `passport number: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "PASSPORT_NUMBER", sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "passport_no",
			input: `passport no: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "PASSPORT_NUMBER", sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "passport_num",
			input: `passport num: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "PASSPORT_NUMBER", sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "passport_hash",
			input: `passport #: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "PASSPORT_NUMBER", sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "travel_document_number",
			input: `travel document number: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "PASSPORT_NUMBER", sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "travel_doc_no",
			input: `travel doc no: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "PASSPORT_NUMBER", sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "passport_book_number",
			input: `passport book number: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "PASSPORT_NUMBER", sensitiveinformation.LikelihoodLikely)},
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

func TestDetector_VeryLikely_Us(t *testing.T) {
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
			input: `us passport: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_passport_right",
			input: `passport us: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "usa_passport_left",
			input: `usa passport: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "usa_passport_right",
			input: `passport usa: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "united_states_passport_left",
			input: `united states passport: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "united_states_passport_right",
			input: `passport united states: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "american_passport_left",
			input: `american passport: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "american_passport_right",
			input: `passport american: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_passport_number_left",
			input: `us passport number: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_passport_number_right",
			input: `passport number us: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_passport_no_left",
			input: `us passport no: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_passport_no_right",
			input: `passport no us: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_pass_no_left",
			input: `us pass no: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_pass_no_right",
			input: `pass no us: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_passport_hash_left",
			input: `us passport #: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_passport_hash_right",
			input: `passport us #: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_travel_document_left",
			input: `us travel document: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_travel_document_right",
			input: `travel document us: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_travel_doc_left",
			input: `us travel doc: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "us_travel_doc_right",
			input: `travel doc us: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "united_states_travel_document_left",
			input: `united states travel document: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "united_states_travel_document_right",
			input: `travel document united states: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "case_insensitive_left",
			input: `US PASSPORT: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "case_insensitive_right",
			input: `PASSPORT US: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "US_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
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

func TestDetector_VeryLikely_Uk(t *testing.T) {
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
			name:  "uk_passport_left",
			input: `uk passport: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "uk_passport_right",
			input: `passport uk: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "united_kingdom_passport_left",
			input: `united kingdom passport: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "united_kingdom_passport_right",
			input: `passport united kingdom: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "british_passport_left",
			input: `british passport: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "british_passport_right",
			input: `passport british: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "uk_passport_number_left",
			input: `uk passport number: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "uk_passport_number_right",
			input: `passport number uk: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "uk_passport_no_left",
			input: `uk passport no: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "uk_passport_no_right",
			input: `passport no uk: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "uk_pass_no_left",
			input: `uk pass no: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "uk_pass_no_right",
			input: `pass no uk: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "uk_passport_hash_left",
			input: `uk passport #: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "uk_passport_hash_right",
			input: `passport uk #: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "uk_travel_document_left",
			input: `uk travel document: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "uk_travel_document_right",
			input: `travel document uk: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "uk_travel_doc_left",
			input: `uk travel doc: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "uk_travel_doc_right",
			input: `travel doc uk: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "united_kingdom_travel_document_left",
			input: `united kingdom travel document: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "united_kingdom_travel_document_right",
			input: `travel document united kingdom: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "case_insensitive_left",
			input: `UK PASSPORT: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "case_insensitive_right",
			input: `PASSPORT UK: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "UK_PASSPORT_NUMBER", sensitiveinformation.LikelihoodVeryLikely)},
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
			input: `12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "PASSPORT_NUMBER", sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "number_with_unrelated_text",
			input: `some random text 12345678 more random text`,
			want:  []veles.Secret{buildExpectedResult([]byte("12345678"), "PASSPORT_NUMBER", sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name: "number_in_unrelated_list",
			input: `user_id,value
    123,12345678
    `,
			want: []veles.Secret{buildExpectedResult([]byte("12345678"), "PASSPORT_NUMBER", sensitiveinformation.LikelihoodUnlikely)},
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
			name:  "invalid_number_missing_number",
			input: `1234567`,
		},
		{
			name:  "invalid_number_dash_separator",
			input: `123-45678`,
		},
		{
			name:  "invalid_number_space_separator",
			input: `123 45678`,
		},
		{
			name:  "text_without_number",
			input: `not a passport number`,
		},
		{
			name:  "invalid_number_too_long",
			input: `123456789`,
		},
		{
			name:  "invalid_first_character_alpha",
			input: `A2345678`,
		},
		{
			name:  "number_within_longer_string",
			input: `asdf12345678asdf`,
		},
		{
			name:  "number_within_underscores",
			input: `asdf_12345678_asdf`,
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
		123,12345678
		`,
			want: []veles.Secret{buildExpectedResult([]byte("12345678"), "PASSPORT_NUMBER", sensitiveinformation.LikelihoodUnlikely)},
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

func buildExpectedResult(blob []byte, name string, likelihood sensitiveinformation.Likelihood) sensitiveinformation.SensitiveInformation {
	return sensitiveinformation.SensitiveInformation{
		InfoType: sensitiveinformation.InfoType{
			Name:        name,
			Sensitivity: sensitiveinformation.SensitivityLevelHigh,
		},
		Likelihood: likelihood,
		Raw:        blob,
	}
}
