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

package discordbottoken_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/discordbottoken"
)

const validatorTestToken = "MTIzNDU2Nzg5MDEyMzQ1Njc4.YAaBbC.dEFGhijklMNOPqrSTUVwxyzAB12"

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "discord.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

func mockDiscordServer(t *testing.T, expectedToken string, statusCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v10/users/@me" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth != "Bot "+expectedToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(statusCode)
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name       string
		token      string
		statusCode int
		want       veles.ValidationStatus
	}{
		{
			name:       "valid bot token",
			token:      validatorTestToken,
			statusCode: http.StatusOK,
			want:       veles.ValidationValid,
		},
		{
			name:       "invalid bot token",
			token:      "invalid.token.value",
			statusCode: http.StatusUnauthorized,
			want:       veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := mockDiscordServer(t, validatorTestToken, tc.statusCode)
			defer server.Close()

			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			validator := discordbottoken.NewValidator()
			validator.HTTPC = client

			got, err := validator.Validate(
				t.Context(),
				discordbottoken.DiscordBotToken{Token: tc.token},
			)

			if err != nil {
				t.Fatalf("Validate() error = %v", err)
			}

			if got != tc.want {
				t.Fatalf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}
