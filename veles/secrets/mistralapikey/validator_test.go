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

package mistralapikey_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/mistralapikey"
	"github.com/google/osv-scalibr/veles/velestest"
)

const validatorTestKey = "abcdefghij1234567890ABCDEFGHIJ12"

func TestAcceptValidator(t *testing.T) {
	brokenValidator := mistralapikey.NewValidator()
	brokenValidator.HTTPC = velestest.BrokenClient

	velestest.AcceptValidator(
		t,
		mistralapikey.NewValidator(),
		velestest.WithTrueNegatives(mistralapikey.MistralAPIKey{
			Key: "osvscalibrinvalidmistralkey000000",
		}),
		velestest.WithBrokenTransport(brokenValidator),
	)
}

// mockTransport redirects requests to the test server.
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL.
	if req.URL.Host == "api.mistral.ai" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockMistralServer creates a mock Mistral API server for testing.
func mockMistralServer(t *testing.T, expectedKey string, statusCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a GET request to the expected endpoint.
		if r.Method != http.MethodGet || r.URL.Path != "/v1/models" {
			t.Errorf("unexpected request: %s %s, expected: GET /v1/models", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check Authorization header.
		authHeader := r.Header.Get("Authorization")
		if !strings.HasSuffix(authHeader, expectedKey) {
			t.Errorf("expected Authorization header to end with key %s, got: %s", expectedKey, authHeader)
		}

		// Set response.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		want       veles.ValidationStatus
		wantErr    error
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
		{
			name:       "server_error",
			statusCode: http.StatusInternalServerError,
			want:       veles.ValidationFailed,
			wantErr:    cmpopts.AnyError,
		},
		{
			name:       "bad_gateway",
			statusCode: http.StatusBadGateway,
			want:       veles.ValidationFailed,
			wantErr:    cmpopts.AnyError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server.
			server := mockMistralServer(t, validatorTestKey, tc.statusCode)
			defer server.Close()

			// Create client with custom transport.
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create validator with mock client.
			validator := mistralapikey.NewValidator()
			validator.HTTPC = client

			key := mistralapikey.MistralAPIKey{Key: validatorTestKey}

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
