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

package packagist_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/packagist"
)

func TestAPIKeyValidator(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		want       veles.ValidationStatus
	}{
		{
			name:       "valid_key",
			statusCode: http.StatusOK,
			want:       veles.ValidationValid,
		},
		{
			name:       "invalid_key_unauthorized",
			statusCode: http.StatusUnauthorized,
			want:       veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.statusCode == http.StatusOK {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`[]`))
					return
				}
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(`{"status":"error","message":"An authentication exception occurred."}`))
			}))
			defer server.Close()

			validator := packagist.NewAPIKeyValidator()
			validator.Endpoint = server.URL

			key := packagist.APIKey{
				Key: "packagist_ack_testkey1234567890abcdef1234567890abcdef1234567890abcdef",
			}

			got, err := validator.Validate(context.Background(), key)
			if err != nil {
				t.Errorf("Validate() error = %v, want nil", err)
			}
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAPISecretValidator(t *testing.T) {
	cases := []struct {
		name        string
		statusCode  int
		hasKey      bool
		want        veles.ValidationStatus
		expectError bool
	}{
		{
			name:       "valid_secret_with_key",
			statusCode: http.StatusOK,
			hasKey:     true,
			want:       veles.ValidationValid,
		},
		{
			name:       "invalid_secret_unauthorized",
			statusCode: http.StatusUnauthorized,
			hasKey:     true,
			want:       veles.ValidationInvalid,
		},
		{
			name:        "no_api_key",
			hasKey:      false,
			want:        veles.ValidationFailed,
			expectError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				// Check that it's using HMAC-SHA256 authentication
				if !strings.HasPrefix(auth, "PACKAGIST-HMAC-SHA256") {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				// Check that required parameters are present
				if !strings.Contains(auth, "Key=") || !strings.Contains(auth, "Timestamp=") ||
					!strings.Contains(auth, "Cnonce=") || !strings.Contains(auth, "Signature=") {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				// For testing, accept any properly formatted HMAC request
				if tc.statusCode == http.StatusOK {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`[]`))
					return
				}
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(`{"status":"error","message":"An authentication exception occurred."}`))
			}))
			defer server.Close()

			validator := packagist.NewAPISecretValidator()
			validator.EndpointFunc = func(secret packagist.APISecret) (string, error) {
				if secret.Key == "" {
					return "", errors.New("API key not present")
				}
				return server.URL, nil
			}

			key := ""
			if tc.hasKey {
				key = "packagist_ack_testkey1234567890abcdef1234567890abcdef1234567890abcdef"
			}

			secret := packagist.APISecret{
				Secret: "packagist_acs_testsecret1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				Key:    key,
			}

			got, err := validator.Validate(context.Background(), secret)

			if tc.expectError {
				if err == nil {
					t.Error("Validate() error = nil, want error")
				}
			} else {
				if err != nil {
					t.Errorf("Validate() error = %v, want nil", err)
				}
			}

			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}
