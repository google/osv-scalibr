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

package hashicorpvault

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/velestest"
)

func TestTokenDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		NewTokenDetector(),
		"hvs.CAESIB8KI2QJk0ePUYdOQXaxl0",
		Token{Token: "hvs.CAESIB8KI2QJk0ePUYdOQXaxl0"},
	)
}

func TestNewTokenDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []veles.Secret
	}{
		{
			name:  "hvs token",
			input: "VAULT_TOKEN=hvs.CAESIB8KI2QJk0ePUYdOQXaxl0",
			expected: []veles.Secret{
				Token{Token: "hvs.CAESIB8KI2QJk0ePUYdOQXaxl0"},
			},
		},
		{
			name:  "hvb token",
			input: "export VAULT_TOKEN=hvb.AAAAAQJz0zBvWUNOIKTkDhYX",
			expected: []veles.Secret{
				Token{Token: "hvb.AAAAAQJz0zBvWUNOIKTkDhYX"},
			},
		},
		{
			name:  "multiple tokens",
			input: "hvs.CAESIB8KI2QJk0ePUYdOQXaxl0 and hvb.AAAAAQJz0zBvWUNOIKTkDhYX",
			expected: []veles.Secret{
				Token{Token: "hvs.CAESIB8KI2QJk0ePUYdOQXaxl0"},
				Token{Token: "hvb.AAAAAQJz0zBvWUNOIKTkDhYX"},
			},
		},
		{
			name:  "long token",
			input: "hvs.CAESIDOKRphWTHBGVCFxpRF0iKHJsQUF6aMSCxdGH6_7n8MbGicKImh2cy5raWJjQjdrcmpYOEoxanUza2ljZGJhYwkEGPDt4a4",
			expected: []veles.Secret{
				Token{Token: "hvs.CAESIDOKRphWTHBGVCFxpRF0iKHJsQUF6aMSCxdGH6_7n8MbGicKImh2cy5raWJjQjdrcmpYOEoxanUza2ljZGJhYwkEGPDt4a4"},
			},
		},
		{
			name:     "no token",
			input:    "some random text without vault tokens",
			expected: nil,
		},
		{
			name:     "invalid prefix",
			input:    "hvx.CAESIB8KI2QJk0ePUYdOQXaxl0",
			expected: nil,
		},
		{
			name:     "too short",
			input:    "hvs.short",
			expected: nil,
		},
	}

	engine, err := veles.NewDetectionEngine([]veles.Detector{NewTokenDetector()})
	if err != nil {
		t.Fatalf("Failed to create detection engine: %v", err)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := strings.NewReader(test.input)
			secrets, err := engine.Detect(t.Context(), reader)
			if err != nil {
				t.Fatalf("Detect() returned error: %v", err)
			}
			if diff := cmp.Diff(test.expected, secrets); diff != "" {
				t.Errorf("Detect() returned unexpected result (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestNewAppRoleDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []veles.Secret
	}{
		{
			name:  "single UUID with ROLE_ID context",
			input: "ROLE_ID=12345678-1234-1234-1234-123456789012",
			expected: []veles.Secret{
				AppRoleCredentials{RoleID: "12345678-1234-1234-1234-123456789012"},
			},
		},
		{
			name:  "context-aware credential pair",
			input: "role_id: 87654321-4321-4321-4321-210987654321\nsecret_id: 11111111-2222-3333-4444-555555555555",
			expected: []veles.Secret{
				AppRoleCredentials{
					RoleID:   "87654321-4321-4321-4321-210987654321",
					SecretID: "11111111-2222-3333-4444-555555555555",
				},
			},
		},
		{
			name:  "standalone role_id with context",
			input: "role_id: 87654321-4321-4321-4321-210987654321",
			expected: []veles.Secret{
				AppRoleCredentials{RoleID: "87654321-4321-4321-4321-210987654321"},
			},
		},
		{
			name:  "standalone secret_id with context",
			input: "secret_id: 11111111-2222-3333-4444-555555555555",
			expected: []veles.Secret{
				AppRoleCredentials{SecretID: "11111111-2222-3333-4444-555555555555"},
			},
		},
		{
			name:  "UUID without context",
			input: "some random UUID: 12345678-1234-1234-1234-123456789012 in text",
			expected: []veles.Secret{
				AppRoleCredentials{ID: "12345678-1234-1234-1234-123456789012"},
			},
		},
		{
			name:     "mixed case UUID with invalid hex chars",
			input:    "ROLE_ID=12345678-ABCD-1234-EFGH-123456789012",
			expected: nil, // G and H are not valid hex characters
		},
		{
			name:     "no UUID",
			input:    "some random text without UUIDs",
			expected: nil,
		},
		{
			name:     "invalid UUID format",
			input:    "12345678-1234-1234-1234-12345678901", // too short
			expected: nil,
		},
		{
			name:  "invalid UUID format with extra chars",
			input: "12345678-1234-1234-1234-1234567890123", // too long
			expected: []veles.Secret{
				AppRoleCredentials{ID: "12345678-1234-1234-1234-123456789012"},
			}, // The regex will match the valid portion
		},
		{
			name:     "invalid UUID format missing hyphens",
			input:    "1234567812341234123412345678901",
			expected: nil,
		},
	}

	engine, err := veles.NewDetectionEngine([]veles.Detector{NewAppRoleDetector()})
	if err != nil {
		t.Fatalf("Failed to create detection engine: %v", err)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := strings.NewReader(test.input)
			secrets, err := engine.Detect(t.Context(), reader)
			if err != nil {
				t.Fatalf("Detect() returned error: %v", err)
			}
			if diff := cmp.Diff(test.expected, secrets); diff != "" {
				t.Errorf("Detect() returned unexpected result (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestDetector_LargeInput(t *testing.T) {
	// Test that detector can handle large inputs without issues
	largeInput := strings.Repeat("some random text ", 10000) + "hvs.CAESIB8KI2QJk0ePUYdOQXaxl0"

	engine, err := veles.NewDetectionEngine([]veles.Detector{NewTokenDetector()})
	if err != nil {
		t.Fatalf("Failed to create detection engine: %v", err)
	}

	reader := strings.NewReader(largeInput)
	secrets, err := engine.Detect(t.Context(), reader)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	expected := []veles.Secret{
		Token{Token: "hvs.CAESIB8KI2QJk0ePUYdOQXaxl0"},
	}

	if diff := cmp.Diff(expected, secrets); diff != "" {
		t.Errorf("Detect() returned unexpected result (-expected +got):\n%s", diff)
	}
}

func TestDetector_EmptyInput(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{NewTokenDetector()})
	if err != nil {
		t.Fatalf("Failed to create detection engine: %v", err)
	}

	reader := strings.NewReader("")
	secrets, err := engine.Detect(t.Context(), reader)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if len(secrets) != 0 {
		t.Errorf("Expected no secrets from empty input, got %d secrets", len(secrets))
	}
}

// Note: TestDetector_ErrorReading was removed because the DetectionEngine
// handles reader errors at a different level than individual detectors.

func TestDetect_IncorrectFormat(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "invalid token prefix",
			input: "hvx.CAESIB8KI2QJk0ePUYdOQXaxl0",
		},
		{
			name:  "token too short",
			input: "hvs.ABC",
		},
		{
			name:  "wrong separator",
			input: "hvs-CAESIB8KI2QJk0ePUYdOQXaxl0",
		},
		{
			name:  "invalid UUID format - missing hyphens",
			input: "role_id: 12345678123412341234123456789012",
		},
		{
			name:  "invalid UUID format - wrong length",
			input: "secret_id: 12345678-1234-1234-1234-12345678901",
		},
		{
			name:  "invalid UUID format - invalid hex characters",
			input: "role_id: 12345678-1234-1234-1234-12345678901G",
		},
		{
			name:  "malformed token with valid prefix",
			input: "hvs.",
		},
		{
			name:  "legacy token too short",
			input: "s.ABC",
		},
		{
			name:  "mixed valid and invalid",
			input: "hvx.invalid and role_id: invalid-uuid-format",
		},
	}

	// Test both token and AppRole detectors
	detectors := []struct {
		name     string
		detector veles.Detector
	}{
		{"TokenDetector", NewTokenDetector()},
		{"AppRoleDetector", NewAppRoleDetector()},
	}

	for _, detectorTest := range detectors {
		t.Run(detectorTest.name, func(t *testing.T) {
			engine, err := veles.NewDetectionEngine([]veles.Detector{detectorTest.detector})
			if err != nil {
				t.Fatalf("Failed to create detection engine: %v", err)
			}

			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					reader := strings.NewReader(test.input)
					secrets, err := engine.Detect(t.Context(), reader)
					if err != nil {
						t.Fatalf("Detect() returned error: %v", err)
					}

					// All these inputs should produce no valid secrets
					if len(secrets) != 0 {
						t.Errorf("Expected no secrets for invalid format '%s', but got %d secrets: %v",
							test.input, len(secrets), secrets)
					}
				})
			}
		})
	}
}
