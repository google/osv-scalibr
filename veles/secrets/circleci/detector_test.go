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

package circleci_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/circleci"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	testPAT     = "CCIPAT_GHFzqc7fRZ2GviZQ7hbdeb_9f54ac82eef4bb69a8fece88199a7414f32d8b36"
	testProject = "CCIPRJ_Nw1xCXXyTW8uvdkHKLNUqK_4ad9cadd8b2b29d02a49ed03720fac5644f66c92"
)

func TestPersonalAccessTokenDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		circleci.NewPersonalAccessTokenDetector(),
		testPAT,
		circleci.PersonalAccessToken{Token: testPAT},
	)
}

func TestProjectTokenDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		circleci.NewProjectTokenDetector(),
		testProject,
		circleci.ProjectToken{Token: testProject},
	)
}

func TestPersonalAccessTokenDetector_TruePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{circleci.NewPersonalAccessTokenDetector()})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "PAT in config",
			input: `circle_token: CCIPAT_GHFzqc7fRZ2GviZQ7hbdeb_9f54ac82eef4bb69a8fece88199a7414f32d8b36`,
			want: []veles.Secret{
				circleci.PersonalAccessToken{Token: testPAT},
			},
		},
		{
			name:  "PAT in environment variable",
			input: `export CIRCLECI_TOKEN="CCIPAT_GHFzqc7fRZ2GviZQ7hbdeb_9f54ac82eef4bb69a8fece88199a7414f32d8b36"`,
			want: []veles.Secret{
				circleci.PersonalAccessToken{Token: testPAT},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPersonalAccessTokenDetector_TrueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{circleci.NewPersonalAccessTokenDetector()})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Invalid prefix",
			input: `CCIPAT_invalid`,
		},
		{
			name:  "Wrong hex length",
			input: `CCIPAT_test_123abc`,
		},
		{
			name:  "Missing underscore",
			input: `CCIPATGHFzqc7fRZ2GviZQ7hbdeb9f54ac82eef4bb69a8fece88199a7414f32d8b36`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(got) > 0 {
				t.Errorf("Expected no secrets, got %d", len(got))
			}
		})
	}
}

func TestProjectTokenDetector_TruePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{circleci.NewProjectTokenDetector()})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "Project token in config",
			input: `token: CCIPRJ_Nw1xCXXyTW8uvdkHKLNUqK_4ad9cadd8b2b29d02a49ed03720fac5644f66c92`,
			want: []veles.Secret{
				circleci.ProjectToken{Token: testProject},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestProjectTokenDetector_TrueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{circleci.NewProjectTokenDetector()})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Invalid prefix",
			input: `CCIPRJ_invalid`,
		},
		{
			name:  "Wrong hex length",
			input: `CCIPRJ_test_123abc`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(got) > 0 {
				t.Errorf("Expected no secrets, got %d", len(got))
			}
		})
	}
}
