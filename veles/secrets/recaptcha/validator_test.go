// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package recaptcha_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/recaptcha"
)

// mockTransport redirects requests to the test server for the configured hosts.
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "www.google.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

func TestValidator_Validate(t *testing.T) {
	testCases := []struct {
		name       string
		response   map[string]any
		statusCode int
		wantStatus veles.ValidationStatus
		wantErr    error
	}{
		{
			name: "valid secret",
			response: map[string]any{
				"success":     false,
				"error-codes": []string{"invalid-input-response"},
			},
			statusCode: http.StatusOK,
			wantStatus: veles.ValidationValid,
		},
		{
			name: "invalid secret",
			response: map[string]any{
				"success":     false,
				"error-codes": []string{"invalid-input-secret"},
			},
			statusCode: http.StatusOK,
			wantStatus: veles.ValidationInvalid,
		},
		{
			name:       "http error",
			statusCode: http.StatusInternalServerError,
			wantStatus: veles.ValidationFailed,
			wantErr:    cmpopts.AnyError,
		},
		{
			name:       "bad response body",
			response:   map[string]any{"success": "not a bool"},
			statusCode: http.StatusOK,
			wantStatus: veles.ValidationFailed,
			wantErr:    cmpopts.AnyError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Fatalf("ParseForm() err = %v", err)
				}
				if r.FormValue("secret") == "" {
					t.Errorf("secret not set in form")
				}
				if r.FormValue("response") == "" {
					t.Errorf("response not set in form")
				}

				w.WriteHeader(tc.statusCode)

				// Add JSON response body
				if tc.response != nil {
					w.Header().Set("Content-Type", "application/json")
					if err := json.NewEncoder(w).Encode(tc.response); err != nil {
						t.Fatalf("failed to encode response: %v", err)
					}
				}
			}))
			defer server.Close()

			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			v := recaptcha.NewValidator(recaptcha.WithClient(client))
			status, err := v.Validate(context.Background(), recaptcha.CaptchaSecret{Key: "somekey"})

			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
			}
			if status != tc.wantStatus {
				t.Errorf("Validate() status = %v, want %v", status, tc.wantStatus)
			}
		})
	}
}
