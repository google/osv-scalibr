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
			name:     "hvb token",
			token:    "hvb.AAAAAQJz0zBvWUNOIKTkDhY",
			expected: true,
		},
		{
			name:     "legacy s token",
			token:    "s.VUFMJlFreGZNZOeQQPiSSviF",
			expected: true,
		},
		{
			name:     "legacy b token",
			token:    "b.AUFMJlFreGZNZOeQQPiSSviF",
			expected: true,
		},
		{
			name:     "legacy r token",
			token:    "r.VUFMJlFreGZNZOeQQPiSSviF",
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
			name:     "prefix only hvb",
			token:    "hvb.",
			expected: true,
		},
		{
			name:     "prefix only s",
			token:    "s.",
			expected: true,
		},
		{
			name:     "wrong prefix hvx",
			token:    "hvx.CAESIB8KI2QJk0ePUYdOQXaxl0",
			expected: false,
		},
		{
			name:     "wrong prefix hvp (should be hvb)",
			token:    "hvp.CAESIB8KI2QJk0ePUYdOQXaxl0",
			expected: false,
		},
		{
			name:     "case sensitive - HVS",
			token:    "HVS.CAESIB8KI2QJk0ePUYdOQXaxl0",
			expected: false,
		},
		{
			name:     "invalid format - missing dot",
			token:    "hvs_CAESIB8KI2QJk0ePUYdOQXaxl0",
			expected: false,
		},
		{
			name:     "invalid format - wrong separator",
			token:    "hvs-CAESIB8KI2QJk0ePUYdOQXaxl0",
			expected: false,
		},
		{
			name:     "invalid format - double prefix",
			token:    "hvshvs.CAESIB8KI2QJk0ePUYdOQXaxl0",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := isVaultToken(test.token)
			if result != test.expected {
				t.Errorf("isVaultToken(%q) = %v, want %v", test.token, result, test.expected)
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
		{
			name:     "all special characters",
			uuid:     "!@#$%^&*-()_+-={}[]-\\|;':\",.<>?/~`",
			expected: false,
		},
		{
			name:     "numbers only",
			uuid:     "123456789012345678901234567890123456",
			expected: false,
		},
		{
			name:     "letters only",
			uuid:     "abcdefgh-ijkl-mnop-qrst-uvwxyzabcdef",
			expected: false,
		},
		{
			name:     "mixed valid and invalid hex",
			uuid:     "12345678-abcd-xyzt-1234-123456789012",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := isUUID(test.uuid)
			if result != test.expected {
				t.Errorf("isUUID(%q) = %v, want %v", test.uuid, result, test.expected)
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
		{
			name:     "almost valid UUID - wrong format",
			s:        "12345678_1234_1234_1234_123456789012",
			expected: false,
		},
		{
			name:     "truncated UUID",
			s:        "12345678-1234-1234-1234",
			expected: false,
		},
		{
			name:     "extended UUID",
			s:        "12345678-1234-1234-1234-123456789012-extra",
			expected: false,
		},
		{
			name:     "mixed case valid UUID",
			s:        "12345678-ABCD-1234-EFAB-123456789012",
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := isAppRoleCredential(test.s)
			if result != test.expected {
				t.Errorf("isAppRoleCredential(%q) = %v, want %v", test.s, result, test.expected)
			}
		})
	}
}
