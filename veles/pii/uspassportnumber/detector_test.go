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
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	oldValidUSPassportNumber = "123456789"
	newValidUSPassportNumber = "A12345678"
)

func TestDetectorAcceptance_OldNumber(t *testing.T) {
	velestest.AcceptDetector(
		t,
		NewDetector(),
		fmt.Sprintf(`passport:%s`, oldValidUSPassportNumber),
		USPassportNumber{Value: oldValidUSPassportNumber},
	)
}

func TestDetectorAcceptance_NewNumber(t *testing.T) {
	velestest.AcceptDetector(
		t,
		NewDetector(),
		fmt.Sprintf(`passport:%s`, newValidUSPassportNumber),
		USPassportNumber{Value: newValidUSPassportNumber},
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
			name: "json log pretty old",
			input: fmt.Sprintf(`{
			"level": "INFO",
			"user_id": "1234",
			"passport_number": "%s"
		}
		`, oldValidUSPassportNumber),
			want: []veles.Secret{USPassportNumber{Value: oldValidUSPassportNumber}},
		},
		{
			name: "json log pretty new",
			input: fmt.Sprintf(`{
			"level": "INFO",
			"user_id": "1234",
			"passport_number": "%s"
		}
		`, newValidUSPassportNumber),
			want: []veles.Secret{USPassportNumber{Value: newValidUSPassportNumber}},
		},
		{
			name:  "json log minified old",
			input: fmt.Sprintf(`{"level":"INFO","user_id":"1234","passport_number":"%s"}`, oldValidUSPassportNumber),
			want:  []veles.Secret{USPassportNumber{Value: oldValidUSPassportNumber}},
		},
		{
			name:  "json log minified new",
			input: fmt.Sprintf(`{"level":"INFO","user_id":"1234","passport_number":"%s"}`, newValidUSPassportNumber),
			want:  []veles.Secret{USPassportNumber{Value: newValidUSPassportNumber}},
		},
		{
			name: "xml log pretty old",
			input: fmt.Sprintf(`<log>
			<user_id>1234</user_id>
			<passport_number>%s</passport_number>
		</log>
		`, oldValidUSPassportNumber),
			want: []veles.Secret{USPassportNumber{Value: oldValidUSPassportNumber}},
		},
		{
			name: "xml log pretty new",
			input: fmt.Sprintf(`<log>
			<user_id>1234</user_id>
			<passport_number>%s</passport_number>
		</log>
		`, newValidUSPassportNumber),
			want: []veles.Secret{USPassportNumber{Value: newValidUSPassportNumber}},
		},
		{
			name:  "xml log minified old",
			input: fmt.Sprintf("<log><user_id>1234</user_id><passport_number>%s</passport_number></log>", oldValidUSPassportNumber),
			want:  []veles.Secret{USPassportNumber{Value: oldValidUSPassportNumber}},
		},
		{
			name:  "xml log minified new",
			input: fmt.Sprintf("<log><user_id>1234</user_id><passport_number>%s</passport_number></log>", newValidUSPassportNumber),
			want:  []veles.Secret{USPassportNumber{Value: newValidUSPassportNumber}},
		},
		{
			name: "yaml log old",
			input: fmt.Sprintf(`user_id: "1234"
		passport_number: %s
		`, oldValidUSPassportNumber),
			want: []veles.Secret{USPassportNumber{Value: oldValidUSPassportNumber}},
		},
		{
			name: "yaml log new",
			input: fmt.Sprintf(`user_id: "1234"
		passport_number: %s
		`, newValidUSPassportNumber),
			want: []veles.Secret{USPassportNumber{Value: newValidUSPassportNumber}},
		},
		{
			name: "csv log old",
			input: fmt.Sprintf(`user_id,passport_number
		dummy_data0,dummy_data0
		dummy_data0,dummy_data0
		dummy_data0,dummy_data0
		dummy_data0,dummy_data0
		dummy_data0,dummy_data0
		dummy_data0,dummy_data0
		dummy_data0,dummy_data0
		dummy_data0,dummy_data0
		dummy_data0,dummy_data0
		1234,%s
		`, oldValidUSPassportNumber),
			want: []veles.Secret{USPassportNumber{Value: oldValidUSPassportNumber}},
		},
		{
			name: "csv log new",
			input: fmt.Sprintf(`user_id,passport_number
		dummy_data0,dummy_data0
		dummy_data0,dummy_data0
		dummy_data0,dummy_data0
		dummy_data0,dummy_data0
		dummy_data0,dummy_data0
		dummy_data0,dummy_data0
		dummy_data0,dummy_data0
		dummy_data0,dummy_data0
		dummy_data0,dummy_data0
		1234,%s
		`, newValidUSPassportNumber),
			want: []veles.Secret{USPassportNumber{Value: newValidUSPassportNumber}},
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
			name:  "old valid number with missing context",
			input: oldValidUSPassportNumber,
		},
		{
			name:  "new valid number with missing context",
			input: newValidUSPassportNumber,
		},
		{
			name:  "malformed old number missing digit",
			input: `12345678`,
		},
		{
			name:  "malformed new number missing digit",
			input: `A1234567`,
		},
		{
			name:  "malformed new number missing character",
			input: `12345678`,
		},
		{
			name:  "valid old number with invalid context",
			input: fmt.Sprintf("Lorem ipsum dolor sit amet %s, consectetur adipiscing elit", oldValidUSPassportNumber),
		},
		{
			name:  "valid new number with invalid context",
			input: fmt.Sprintf("Lorem ipsum dolor sit amet %s, consectetur adipiscing elit", newValidUSPassportNumber),
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
