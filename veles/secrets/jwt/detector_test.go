// Copyright 2025 Google LLC
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

package jwt_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/jwt"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	testJWT    = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`
	testJWTAlt = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJvc2NhbGliLXRlc3QiLCJhdWQiOiJleGFtcGxlLmNvbSIsImV4cCI6NDQ2ODg3MDQ5MX0.Q5rFj8b0cR2pD7eL1O4mK3vT5wA6xY7zB8C9dE0fG1hI2jJ3kL4mN5oP6qR7sT8uV9wX0yZ1a2b3c4d5e6f7g`
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		jwt.NewDetector(),
		testJWT,
		jwt.Token{Value: testJWT},
	)
}

// TestJWTDetector_TruePositives verifies that the detector finds valid JWT tokens.
func TestJWTDetector_TruePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{jwt.NewDetector()})
	if err != nil {
		t.Fatalf("Failed to initialize detection engine: %v", err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple_matching_string",
		input: testJWT,
		want: []veles.Secret{
			jwt.Token{Value: testJWT},
		},
	}, {
		name:  "token_in_surrounding_text_(Bearer_token)",
		input: "Authorization: Bearer " + testJWT + " end",
		want: []veles.Secret{
			jwt.Token{Value: testJWT},
		},
	}, {
		name:  "multiple_distinct_matches",
		input: testJWT + "\n" + testJWTAlt,
		want: []veles.Secret{
			jwt.Token{Value: testJWT},
			jwt.Token{Value: testJWTAlt},
		},
	}}

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

// TestJWTDetector_TrueNegatives verifies that the detector ignores invalid, non-JWT strings.
func TestJWTDetector_TrueNegative(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{jwt.NewDetector()})
	if err != nil {
		t.Fatalf("Failed to initialize detection engine: %v", err)
	}

	cases := []struct {
		name  string
		input string
	}{{
		name:  "empty_input",
		input: "",
	}, {
		name:  "not_enough_segments",
		input: `header.payload`,
	}, {
		name:  "invalid_base64_characters",
		input: `eyJh!!ciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.b.c`,
	}, {
		name:  "invalid_header",
		input: `eyJhbGciOiJII1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`,
	}, {
		name:  "invalid_payload",
		input: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			// We expect no secrets to be found.
			var want []veles.Secret
			if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
