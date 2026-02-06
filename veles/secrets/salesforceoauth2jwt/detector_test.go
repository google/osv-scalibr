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

package salesforceoauth2jwt_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/salesforceoauth2jwt"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	validClientID      = "3MVG123456789.ABCDEF.ABC11112222223456789ABC123456789ABC1"
	validUsername      = "yuvraj@saxena.com"
	validPrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD...
-----END PRIVATE KEY-----`
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		salesforceoauth2jwt.NewDetector(),
		validClientID+"\n"+validUsername+"\n"+validPrivateKeyPEM,
		salesforceoauth2jwt.Credentials{ID: validClientID, Username: validUsername, PrivateKey: validPrivateKeyPEM},
	)
}

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{salesforceoauth2jwt.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	privateKeySample := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD...
-----END PRIVATE KEY-----`

	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		// --- Empty or invalid input ---
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
		{
			name:  "random text only",
			input: "This file contains no Salesforce credentials",
			want:  nil,
		},

		// --- Invalid patterns ---
		{
			name:  "invalid client ID prefix",
			input: "2MVG123456789.AB_CDEF.ABC123456789",
			want:  nil,
		},
		{
			name:  "invalid email format",
			input: "3MVG123456789.ABCDEF123456789 user(at)email(dot)com",
			want:  nil,
		},
		{
			name: "invalid private key missing end block",
			input: `3MVG123456789.AB_CDEF.ABC123456789 test@example.com
-----BEGIN PRIVATE KEY-----
AAAAA`,
			want: nil,
		},

		// --- Valid tuple (happy path) ---
		{
			name: "valid_id_username_privatekey",
			input: `3MVG123456789.AB_CDEF.ABC123456789
test.user@example.com
` + privateKeySample,
			want: []veles.Secret{
				salesforceoauth2jwt.Credentials{
					ID:         "3MVG123456789.AB_CDEF.ABC123456789",
					Username:   "test.user@example.com",
					PrivateKey: privateKeySample,
				},
			},
		},

		// Multiple tuples in one file
		{
			name: "multiple_credential_sets",
			input: `
3MVGAAAAAA1111111111111111111
admin1@example.com
` + privateKeySample + `

3MVGAAAAAA2222222222222222222
dev.user@example.org
` + privateKeySample,
			want: []veles.Secret{
				salesforceoauth2jwt.Credentials{
					ID:         "3MVGAAAAAA1111111111111111111",
					Username:   "admin1@example.com",
					PrivateKey: privateKeySample,
				},
				salesforceoauth2jwt.Credentials{
					ID:         "3MVGAAAAAA2222222222222222222",
					Username:   "dev.user@example.org",
					PrivateKey: privateKeySample,
				},
			},
		},

		// Multiple tuples in one file (reverse order)
		{
			name: "multiple_credential_sets_reverse_order",
			input: `
3MVGAAAAAA2222222222222222222
dev.user@example.org
` + privateKeySample + `

3MVGAAAAAA1111111111111111111
admin1@example.com
` + privateKeySample,
			want: []veles.Secret{
				salesforceoauth2jwt.Credentials{
					ID:         "3MVGAAAAAA2222222222222222222",
					Username:   "dev.user@example.org",
					PrivateKey: privateKeySample,
				},
				salesforceoauth2jwt.Credentials{
					ID:         "3MVGAAAAAA1111111111111111111",
					Username:   "admin1@example.com",
					PrivateKey: privateKeySample,
				},
			},
		},

		// Test proximity: ID + Email far away, key beyond MaxDistance (should not match)
		{
			name: "id_and_username_with_private_key_far_away",
			input: `3MVG123456789.AB_CDEF.ABC123456789
test@example.com

` + strings.Repeat("X", 12*1024) + `
` + privateKeySample,
			want: nil,
		},

		// Test extra noise: detect only valid combinations
		{
			name: "mixed_valid_and_invalid_blocks",
			input: `
invalid_id: 4MVG9999999INVALID
test1@example.com
` + privateKeySample + `

3MVGABCDE123456789ABCDEFGHIJK
invalid_email_format
` + privateKeySample + `

3MVGXYZ987654321ABCDEFGHIJKLM
valid.user@example.org
` + privateKeySample,
			want: []veles.Secret{
				salesforceoauth2jwt.Credentials{
					ID:         "3MVGXYZ987654321ABCDEFGHIJKLM",
					Username:   "valid.user@example.org",
					PrivateKey: privateKeySample,
				},
				salesforceoauth2jwt.Credentials{
					ID:         "3MVGABCDE123456789ABCDEFGHIJK",
					Username:   "test1@example.com",
					PrivateKey: privateKeySample,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v", err)
			}

			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
