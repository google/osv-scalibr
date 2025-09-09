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
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/veles"
)

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
			name:  "hvp token",
			input: "export VAULT_TOKEN=hvp.AAAAAQJz0zBvWUNOIKTkDhY",
			expected: []veles.Secret{
				Token{Token: "hvp.AAAAAQJz0zBvWUNOIKTkDhY"},
			},
		},
		{
			name:  "multiple tokens",
			input: "hvs.CAESIB8KI2QJk0ePUYdOQXaxl0 and hvp.AAAAAQJz0zBvWUNOIKTkDhY",
			expected: []veles.Secret{
				Token{Token: "hvs.CAESIB8KI2QJk0ePUYdOQXaxl0"},
				Token{Token: "hvp.AAAAAQJz0zBvWUNOIKTkDhY"},
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
			secrets, err := engine.Detect(context.Background(), reader)
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
			name:  "single UUID",
			input: "ROLE_ID=12345678-1234-1234-1234-123456789012",
			expected: []veles.Secret{
				AppRoleCredentials{RoleID: "12345678-1234-1234-1234-123456789012", SecretID: ""},
			},
		},
		{
			name:  "multiple UUIDs",
			input: "role_id: 87654321-4321-4321-4321-210987654321\nsecret_id: 11111111-2222-3333-4444-555555555555",
			expected: []veles.Secret{
				AppRoleCredentials{RoleID: "87654321-4321-4321-4321-210987654321", SecretID: ""},
				AppRoleCredentials{RoleID: "11111111-2222-3333-4444-555555555555", SecretID: ""},
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
				AppRoleCredentials{RoleID: "12345678-1234-1234-1234-123456789012", SecretID: ""},
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
			secrets, err := engine.Detect(context.Background(), reader)
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
	secrets, err := engine.Detect(context.Background(), reader)
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
	secrets, err := engine.Detect(context.Background(), reader)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if len(secrets) != 0 {
		t.Errorf("Expected no secrets from empty input, got %d secrets", len(secrets))
	}
}

// Note: TestDetector_ErrorReading was removed because the DetectionEngine
// handles reader errors at a different level than individual detectors.
