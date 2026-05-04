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

package mongodbatlasapikey_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/mongodbatlasapikey"
)

const (
	validPublicKey  = "abcdef01"
	validPrivateKey = "12345678-abcd-1234-abcd-123456789012"
)

// mockAtlasServer creates a mock MongoDB Atlas API server for testing.
// It implements HTTP Digest Authentication.
func mockAtlasServer(t *testing.T, expectedPublicKey string, authResponseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			// No auth header: return 401 with Digest challenge.
			w.Header().Set("Www-Authenticate",
				`Digest realm="MMS Public API", nonce="testnonce123", qop="auth", algorithm=MD5`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Verify the username in the digest auth matches the expected public key.
		if expectedPublicKey != "" && !containsUsername(authHeader, expectedPublicKey) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(authResponseCode)
	}))
}

// containsUsername checks if the Authorization header contains the expected username.
func containsUsername(authHeader, username string) bool {
	expected := fmt.Sprintf(`username="%s"`, username)
	return len(authHeader) > 0 && contains(authHeader, expected)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name               string
		publicKey          string
		privateKey         string
		serverExpectedKey  string
		serverResponseCode int
		want               veles.ValidationStatus
		wantErr            error
	}{
		{
			name:               "valid_key",
			publicKey:          validPublicKey,
			privateKey:         validPrivateKey,
			serverExpectedKey:  validPublicKey,
			serverResponseCode: http.StatusOK,
			want:               veles.ValidationValid,
		},
		{
			name:               "valid_key_forbidden_scope",
			publicKey:          validPublicKey,
			privateKey:         validPrivateKey,
			serverExpectedKey:  validPublicKey,
			serverResponseCode: http.StatusForbidden,
			want:               veles.ValidationValid,
		},
		{
			name:               "invalid_key_unauthorized",
			publicKey:          "wrongkey1",
			privateKey:         "00000000-0000-0000-0000-000000000000",
			serverExpectedKey:  validPublicKey,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:       "empty_public_key",
			publicKey:  "",
			privateKey: validPrivateKey,
			want:       veles.ValidationInvalid,
		},
		{
			name:       "empty_private_key",
			publicKey:  validPublicKey,
			privateKey: "",
			want:       veles.ValidationInvalid,
		},
		{
			name:               "server_error",
			publicKey:          validPublicKey,
			privateKey:         validPrivateKey,
			serverExpectedKey:  validPublicKey,
			serverResponseCode: http.StatusInternalServerError,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var server *httptest.Server
			if tc.serverExpectedKey != "" || tc.serverResponseCode != 0 {
				server = mockAtlasServer(t, tc.serverExpectedKey, tc.serverResponseCode)
				defer server.Close()
			}

			validator := mongodbatlasapikey.NewValidator()
			if server != nil {
				validator.Endpoint = server.URL
			}

			key := mongodbatlasapikey.APIKey{
				PublicKey:  tc.publicKey,
				PrivateKey: tc.privateKey,
			}

			got, err := validator.Validate(t.Context(), key)

			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
			}

			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidator_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Www-Authenticate", `Digest realm="MMS Public API", nonce="testnonce", qop="auth"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	validator := mongodbatlasapikey.NewValidator()
	validator.Endpoint = server.URL

	key := mongodbatlasapikey.APIKey{
		PublicKey:  validPublicKey,
		PrivateKey: validPrivateKey,
	}

	// Create a cancelled context.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	got, err := validator.Validate(ctx, key)

	if err == nil {
		t.Errorf("Validate() expected error due to context cancellation, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}
