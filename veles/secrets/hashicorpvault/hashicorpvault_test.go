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
	"testing"
)

func TestIsVaultToken(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected bool
	}{
		{
			name:     "hvs token",
			token:    "hvs.CAESIB8KI2QJk0ePUYdOQXaxl0",
			expected: true,
		},
		{
			name:     "hvp token",
			token:    "hvp.AAAAAQJz0zBvWUNOIKTkDhY",
			expected: true,
		},
		{
			name:     "not a vault token",
			token:    "some-other-token",
			expected: false,
		},
		{
			name:     "empty string",
			token:    "",
			expected: false,
		},
		{
			name:     "prefix only hvs",
			token:    "hvs.",
			expected: true,
		},
		{
			name:     "prefix only hvp",
			token:    "hvp.",
			expected: true,
		},
		{
			name:     "wrong prefix hvx",
			token:    "hvx.CAESIB8KI2QJk0ePUYdOQXaxl0",
			expected: false,
		},
		{
			name:     "case sensitive - HVS",
			token:    "HVS.CAESIB8KI2QJk0ePUYdOQXaxl0",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := IsVaultToken(test.token)
			if result != test.expected {
				t.Errorf("IsVaultToken(%q) = %v, want %v", test.token, result, test.expected)
			}
		})
	}
}

func TestIsUUID(t *testing.T) {
	tests := []struct {
		name     string
		uuid     string
		expected bool
	}{
		{
			name:     "valid UUID v4",
			uuid:     "12345678-1234-1234-1234-123456789012",
			expected: true,
		},
		{
			name:     "valid UUID with lowercase",
			uuid:     "87654321-abcd-efgh-ijkl-210987654321",
			expected: false, // 'g', 'h', 'i', 'j', 'k', 'l' are not valid hex characters
		},
		{
			name:     "valid UUID with mixed case",
			uuid:     "12345678-ABCD-1234-EFGH-123456789012",
			expected: false, // 'G' and 'H' are not valid hex characters
		},
		{
			name:     "valid UUID with valid hex only",
			uuid:     "12345678-abcd-1234-efab-123456789012",
			expected: true,
		},
		{
			name:     "too short",
			uuid:     "12345678-1234-1234-1234-12345678901",
			expected: false,
		},
		{
			name:     "too long",
			uuid:     "12345678-1234-1234-1234-1234567890123",
			expected: false,
		},
		{
			name:     "missing hyphens",
			uuid:     "123456781234123412341234567890123",
			expected: false,
		},
		{
			name:     "wrong hyphen positions",
			uuid:     "1234567-8123-41234-1234-567890123",
			expected: false,
		},
		{
			name:     "empty string",
			uuid:     "",
			expected: false,
		},
		{
			name:     "invalid characters",
			uuid:     "12345678-1234-1234-1234-12345678901z",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := IsUUID(test.uuid)
			if result != test.expected {
				t.Errorf("IsUUID(%q) = %v, want %v", test.uuid, result, test.expected)
			}
		})
	}
}

func TestIsAppRoleCredential(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		expected bool
	}{
		{
			name:     "valid UUID",
			s:        "12345678-1234-1234-1234-123456789012",
			expected: true,
		},
		{
			name:     "invalid format",
			s:        "not-a-uuid",
			expected: false,
		},
		{
			name:     "empty string",
			s:        "",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := IsAppRoleCredential(test.s)
			if result != test.expected {
				t.Errorf("IsAppRoleCredential(%q) = %v, want %v", test.s, result, test.expected)
			}
		})
	}
}
