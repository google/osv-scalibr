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

package nugetapikey_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	nugetapikey "github.com/google/osv-scalibr/veles/secrets/nugetapikey"
)

const (
	validatorTestAPIKey = "oy2kpfknfvsp4a2a2ocqlktwuog2zefehglys3lr3nbe"
)

// mockTransport redirects requests to the test server for the configured hosts.
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL for NuGet API hosts.
	if req.URL.Host == "www.nuget.org" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockNuGetServer creates a mock NuGet /api/v2/package endpoint for testing.
func mockNuGetServer(t *testing.T, expectedKey string, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expect a PUT to /api/v2/package
		if r.Method != http.MethodPut || r.URL.Path != "/api/v2/package" {
			t.Errorf("unexpected request: %s %s, expected: PUT /api/v2/package",
				r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check X-NuGet-ApiKey header contains the expected key
		apiKeyHeader := r.Header.Get("X-NuGet-ApiKey")
		if expectedKey != "" && apiKeyHeader != expectedKey {
			t.Errorf("expected X-NuGet-ApiKey header to be %s, got: %s",
				expectedKey, apiKeyHeader)
		}

		// Verify required headers are present
		if r.Header.Get("X-NuGet-Protocol-Version") != "4.1.0" {
			t.Errorf("expected X-NuGet-Protocol-Version header to be 4.1.0, got: %s",
				r.Header.Get("X-NuGet-Protocol-Version"))
		}
		if r.Header.Get("Content-Type") != "application/octet-stream" {
			t.Errorf("expected Content-Type header to be application/octet-stream, got: %s",
				r.Header.Get("Content-Type"))
		}

		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(statusCode)
		if statusCode == http.StatusBadRequest {
			_, _ = w.Write([]byte("Failed to read the package file. Ensure it is a valid NuGet package with a valid manifest."))
		} else if statusCode == http.StatusForbidden {
			_, _ = w.Write([]byte("The specified API key is invalid, has expired, or does not have permission to access the specified package."))
		}
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		want       veles.ValidationStatus
		wantErr    error
	}{{
		name:       "valid_key",
		statusCode: http.StatusBadRequest,
		want:       veles.ValidationValid,
	}, {
		name:       "invalid_key_forbidden",
		statusCode: http.StatusForbidden,
		want:       veles.ValidationInvalid,
	}, {
		name:       "server_error",
		statusCode: http.StatusInternalServerError,
		want:       veles.ValidationFailed,
		wantErr:    cmpopts.AnyError,
	}, {
		name:       "unauthorized_error",
		statusCode: http.StatusUnauthorized,
		want:       veles.ValidationFailed,
		wantErr:    cmpopts.AnyError,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock server
			server := mockNuGetServer(t, validatorTestAPIKey, tc.statusCode)
			defer server.Close()

			// Create client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create validator with mock client
			validator := nugetapikey.NewValidator()
			validator.HTTPC = client

			// Create test key
			key := nugetapikey.NuGetAPIKey{Key: validatorTestAPIKey}

			// Test validation
			got, err := validator.Validate(context.Background(), key)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
			}

			// Check validation status
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidator_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(nil)
	t.Cleanup(func() {
		server.Close()
	})

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := nugetapikey.NewValidator()
	validator.HTTPC = client

	key := nugetapikey.NuGetAPIKey{Key: validatorTestAPIKey}

	// Create context that is immediately cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Test validation with cancelled context
	got, err := validator.Validate(ctx, key)
	if diff := cmp.Diff(cmpopts.AnyError, err, cmpopts.EquateErrors()); diff != "" {
		t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}

func TestValidator_InvalidRequest(t *testing.T) {
	// For NuGet validator, an "invalid" key is communicated via 403 status.
	server := mockNuGetServer(t, "", http.StatusForbidden)
	defer server.Close()

	// Create client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := nugetapikey.NewValidator()
	validator.HTTPC = client

	testCases := []struct {
		name     string
		key      string
		expected veles.ValidationStatus
	}{{
		name:     "empty_key",
		key:      "",
		expected: veles.ValidationInvalid,
	}, {
		name:     "invalid_key_format",
		key:      "invalid-api-key-format",
		expected: veles.ValidationInvalid,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k := nugetapikey.NuGetAPIKey{Key: tc.key}
			got, err := validator.Validate(context.Background(), k)
			if err != nil {
				t.Errorf("Validate() unexpected error for %s: %v", tc.name, err)
			}
			if got != tc.expected {
				t.Errorf("Validate() = %v, want %v for %s", got, tc.expected, tc.name)
			}
		})
	}
}
