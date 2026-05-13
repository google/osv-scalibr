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

package uspassportnumber

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

func TestDetector(t *testing.T) {
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
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "number_with_keyword_lowercase",
			input: `passport_number: a12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("a12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name: "log_json_pretty",
			input: `{
			"level": "INFO",
			"user_id": "1234",
			"passport_number": "A12345678"
		}
		`,
			want: []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "log_json_minified",
			input: `{"level":"INFO","user_id":"1234","passport_number":"A12345678"}`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name: "log_xml_pretty",
			input: `<log>
			<user_id>1234</user_id>
			<passport_number>A12345678</passport_number>
		</log>
		`,
			want: []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name:  "log_xml_minified",
			input: `<log><user_id>1234</user_id><passport_number>A12345678</passport_number></log>`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name: "log_yaml",
			input: `user_id: "1234"
		passport_number: A12345678
		`,
			want: []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
		},
		{
			name: "log_csv",
			input: `user_id,passport_number
		000,000
		123,A12345678
		`,
			want: []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodVeryLikely)},
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

func TestDetector_LowLikelihood(t *testing.T) {
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
			name:  "valid_number_no_context_keyword",
			input: `A12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte("A12345678"), sensitiveinformation.LikelihoodUnlikely)},
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
