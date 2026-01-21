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

package bitwardenapikey_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/bitwardenapikey"
)

func mockBitwardenServer(t *testing.T, expectedID, expectedSecret string, statusCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.Contains(r.URL.Path, "/connect/token") {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("expected Content-Type application/x-www-form-urlencoded, got: %s", r.Header.Get("Content-Type"))
		}

		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "client_id="+expectedID) {
			t.Errorf("expected body to contain client_id=%s, got: %s", expectedID, string(body))
		}
		if !strings.Contains(string(body), "client_secret="+expectedSecret) {
			t.Errorf("expected body to contain client_secret=%s, got: %s", expectedSecret, string(body))
		}

		w.WriteHeader(statusCode)
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		want       veles.ValidationStatus
	}{
		{
			name:       "valid_credentials",
			statusCode: http.StatusOK,
			want:       veles.ValidationValid,
		},
		{
			name:       "invalid_client_id_or_secret",
			statusCode: http.StatusBadRequest,
			want:       veles.ValidationInvalid,
		},
		{
			name:       "unauthorized",
			statusCode: http.StatusUnauthorized,
			want:       veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := mockBitwardenServer(t, testID, testSecret, tc.statusCode)
			defer server.Close()

			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			validator := bitwardenapikey.NewValidator()
			validator.HTTPC = client

			secret := bitwardenapikey.BitwardenAPIKey{
				ClientID:     testID,
				ClientSecret: testSecret,
			}
			got, err := validator.Validate(t.Context(), secret)

			if err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}

			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Host, "bitwarden.com") {
		req.URL.Scheme = "http"
		req.URL.Host = m.testServer.Listener.Addr().String()
	}
	return http.DefaultTransport.RoundTrip(req)
}
