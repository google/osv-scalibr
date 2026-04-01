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

package ibmcloudapikey_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/ibmcloudapikey"
)

const validAPIKey = "hQ7IfkjEssAt7gM5M3CnDFqulKxOPtIxRuLNxSM4XxxS"

// mockTransport redirects requests to the test server.
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "iam.cloud.ibm.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockIAMServer creates a mock IBM Cloud IAM server for testing.
func mockIAMServer(t *testing.T, expectedKey string, responseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/identity/token" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		apikey := r.FormValue("apikey")
		grantType := r.FormValue("grant_type")

		if grantType != "urn:ibm:params:oauth:grant-type:apikey" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if apikey != expectedKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errorCode":"BXNIM0415E","errorMessage":"Provided API key could not be found."}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(responseCode)
		if responseCode == http.StatusOK {
			_, _ = w.Write([]byte(`{"access_token":"eyJ...","token_type":"Bearer","expires_in":3600}`))
		}
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name               string
		key                string
		serverExpectedKey  string
		serverResponseCode int
		want               veles.ValidationStatus
		wantErr            error
	}{
		{
			name:               "valid_key",
			key:                validAPIKey,
			serverExpectedKey:  validAPIKey,
			serverResponseCode: http.StatusOK,
			want:               veles.ValidationValid,
		},
		{
			name:               "invalid_key",
			key:                "invalidKey_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			serverExpectedKey:  validAPIKey,
			serverResponseCode: http.StatusBadRequest,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "unauthorized_key",
			key:                "wrongKey_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			serverExpectedKey:  validAPIKey,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "server_error",
			key:                validAPIKey,
			serverExpectedKey:  validAPIKey,
			serverResponseCode: http.StatusInternalServerError,
			want:               veles.ValidationFailed,
			wantErr:            cmpopts.AnyError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := mockIAMServer(t, tc.serverExpectedKey, tc.serverResponseCode)
			defer server.Close()

			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			validator := ibmcloudapikey.NewValidator()
			validator.HTTPC = client

			secret := ibmcloudapikey.Secret{Key: tc.key}

			got, err := validator.Validate(t.Context(), secret)

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
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := ibmcloudapikey.NewValidator()
	validator.HTTPC = client

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	secret := ibmcloudapikey.Secret{Key: validAPIKey}

	got, err := validator.Validate(ctx, secret)

	if err == nil {
		t.Error("Validate() expected error due to context cancellation, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}
