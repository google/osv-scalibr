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

package databricksuseraccountoauth2client_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/databricksuseraccountoauth2client"
)

const (
	validatorTestClientID     = "7603a2a8-8220-485f-b2a5-58fa7b60a932"
	validatorTestClientSecret = "dose7d9f306280a357544b0655ed81ef06c9"
	validatorTestAccountID    = "account_id: bd59efba-4444-4444-443f-44444449203"
	expectedTestAccountID     = "bd59efba-4444-4444-443f-44444449203"
)

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == "accounts.cloud.databricks.com" || req.URL.Host == "accounts.gcp.databricks.com" || req.URL.Host == "accounts.azuredatabricks.net" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockDatabricksServer creates a mock Databricks server for testing
func mockDatabricksServer(t *testing.T, expectedClientID string, expectedClientSecret string, expectedAccountID string, serverResponseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a POST request to the expected endpoint
		if r.Method != http.MethodPost || r.URL.Path != "/api/2.0/token/create" {
			t.Errorf("unexpected request: %s %s, expected: POST /api/2.0/token/create", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		clientIDHeader := r.Header.Get("Client_id")
		clientSecretHeader := r.Header.Get("Client_secret")

		// Read request body
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed reading body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body := string(bodyBytes)
		defer r.Body.Close()

		// Check Authorization header and Account-Id
		if !strings.Contains(clientIDHeader, expectedClientID) || !strings.Contains(clientSecretHeader, expectedClientSecret) || !strings.Contains(body, expectedAccountID) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(serverResponseCode)
	}))
}

func TestValidator(t *testing.T) {
	tests := []struct {
		name               string
		id                 string
		secret             string
		accountID          string
		serverResponseCode int
		cancelContext      bool
		want               veles.ValidationStatus
		wantErr            error
		useServer          bool
	}{
		{
			name:               "valid creds",
			id:                 validatorTestClientID,
			secret:             validatorTestClientSecret,
			accountID:          validatorTestAccountID,
			serverResponseCode: http.StatusOK,
			want:               veles.ValidationValid,
		},
		{
			name:               "invalid creds - Client ID",
			id:                 "YUVRAJ SAXENA",
			secret:             validatorTestClientSecret,
			accountID:          validatorTestAccountID,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "invalid creds - Client Secret",
			id:                 validatorTestClientID,
			secret:             "YUVRAJ SAXENA",
			accountID:          validatorTestAccountID,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "invalid creds - Account ID",
			id:                 validatorTestClientID,
			secret:             validatorTestClientSecret,
			accountID:          "YUVRAJ SAXENA",
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "empty Client ID",
			id:                 "",
			secret:             validatorTestClientSecret,
			accountID:          validatorTestAccountID,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "empty Client Secret",
			id:                 validatorTestClientID,
			secret:             "",
			accountID:          validatorTestAccountID,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "empty Account ID",
			id:                 validatorTestClientID,
			secret:             validatorTestClientSecret,
			accountID:          "",
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "context cancelled",
			id:                 validatorTestClientID,
			secret:             validatorTestClientSecret,
			accountID:          validatorTestAccountID,
			serverResponseCode: http.StatusOK,
			cancelContext:      true,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			server := mockDatabricksServer(t, validatorTestClientID, validatorTestClientSecret, expectedTestAccountID, tt.serverResponseCode)
			defer server.Close()

			if tt.cancelContext {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			validator := databricksuseraccountoauth2client.NewValidator()
			if server != nil {
				validator.HTTPC = &http.Client{
					Transport: &mockTransport{testServer: server},
				}
			}

			cred := databricksuseraccountoauth2client.Credentials{
				Secret:    tt.secret,
				ID:        tt.id,
				AccountID: tt.accountID,
			}

			got, err := validator.Validate(ctx, cred)

			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
			}

			if got != tt.want {
				t.Fatalf("Validate: expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestValidate_MultipleEndpoints(t *testing.T) {
	callCount := 0
	ctx := t.Context()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		if r.Method != http.MethodPost ||
			r.URL.Path != "/api/2.0/token/create" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Simulate:
		// 1st endpoint -> Unauthorized
		// 2nd endpoint -> OK
		if callCount == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	validator := databricksuseraccountoauth2client.NewValidator()
	validator.HTTPC = &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	cred := databricksuseraccountoauth2client.Credentials{
		Secret:    validatorTestClientSecret,
		AccountID: validatorTestAccountID,
		ID:        validatorTestClientID,
	}

	got, err := validator.Validate(ctx, cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != veles.ValidationValid {
		t.Fatalf("expected ValidationValid, got %v", got)
	}

	if callCount != 2 {
		t.Fatalf("expected 2 endpoint attempts, got %d", callCount)
	}
}
