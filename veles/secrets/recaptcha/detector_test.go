// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package recaptcha_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/recaptcha"
)

const (
	// A valid-looking but fake reCAPTCHA secret key.
	testKey = "6LdQ89YrAAAAABSEaPf4idV0SsQvKXic1V6pwtur"
)

func TestDetector_TruePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{recaptcha.NewDetector()},
	)
	if err != nil {
		t.Fatalf("veles.NewDetectionEngine(): %v", err)
	}

	testCases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "simple match",
			input: testKey,
			want:  []veles.Secret{recaptcha.CaptchaSecret{Key: testKey}},
		},

		{
			name:  "in quotes",
			input: `"` + testKey + `"`,
			want:  []veles.Secret{recaptcha.CaptchaSecret{Key: testKey}},
		},
		{
			name:  "as variable assignment",
			input: "RECAPTCHA_SECRET=" + testKey,
			want:  []veles.Secret{recaptcha.CaptchaSecret{Key: testKey}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() returned an error: %v", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetector_TrueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine(
		[]veles.Detector{recaptcha.NewDetector()},
	)
	if err != nil {
		t.Fatalf("veles.NewDetectionEngine(): %v", err)
	}

	testCases := []struct {
		name  string
		input string
	}{
		{
			name:  "empty string",
			input: "",
		},
		{
			name:  "wrong starting character",
			input: "5LdQ89YrAAAAABSEaPf4idV0SsQvKXic1V6pwtur",
		},
		{
			name:  "too short",
			input: "6LdQ89YrAAAAABSEaPf4idV0SsQvKXic1V6pwt",
		},
		{
			name:  "invalid characters",
			input: "6LdQ89YrAAAAABSEaPf4idV0SsQvKXic1V6pwt+!",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() returned an error: %v", err)
			}
			if len(got) > 0 {
				t.Errorf("Detect() returned %d secrets, want 0", len(got))
			}
		})
	}
}
