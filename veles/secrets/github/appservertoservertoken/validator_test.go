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

package appservertoservertoken_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/github/appservertoservertoken"
)

const validatorTestKey = `gh` + `s_oJrI3NxJonXega4cd3v1XHDjjMk3jh2ENWzb`

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == "api.github.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockGithubServer creates a mock Github API server for testing
func mockGithubServer(t *testing.T, code int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a GET request to the expected endpoint
		if r.Method != http.MethodGet || r.URL.Path != "/installation/repositories" {
			t.Errorf("unexpected request: %s %s, expected: GET /installation/repositories", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		if code != http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			return
		}

		// Check Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer "+validatorTestKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Set response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}))
}

func TestValidator(t *testing.T) {
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowServer.Close()

	shortCtx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	cases := []struct {
		name    string
		token   string
		server  *httptest.Server
		want    veles.ValidationStatus
		wantErr error
		//nolint:containedctx
		ctx context.Context
	}{
		{
			name:    "slow_server",
			ctx:     shortCtx,
			server:  slowServer,
			want:    veles.ValidationFailed,
			wantErr: cmpopts.AnyError,
		},
		{
			name:   "valid_key",
			token:  validatorTestKey,
			server: mockGithubServer(t, http.StatusOK),
			want:   veles.ValidationValid,
		},
		{
			name:   "invalid_key_unauthorized",
			token:  "random_string",
			server: mockGithubServer(t, http.StatusUnauthorized),
			want:   veles.ValidationInvalid,
		},
		{
			name:   "server_error",
			server: mockGithubServer(t, http.StatusInternalServerError),
			want:   veles.ValidationFailed,
		},
		{
			name:   "bad_gateway",
			server: mockGithubServer(t, http.StatusBadGateway),
			want:   veles.ValidationFailed,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ctx == nil {
				tt.ctx = t.Context() //nolint:fatcontext
			}

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: tt.server},
			}

			// Create a validator with a mock client
			validator := appservertoservertoken.NewValidator(
				appservertoservertoken.WithClient(client),
			)

			// Create a test key
			key := appservertoservertoken.GithubAppServerToServerToken{Token: tt.token}

			// Test validation
			got, err := validator.Validate(tt.ctx, key)

			if !cmp.Equal(tt.wantErr, err, cmpopts.EquateErrors()) {
				t.Fatalf("Validate() error: %v, want %v", err, tt.wantErr)
			}

			if tt.want != got {
				t.Errorf("Validate(): got: %v, want: %v", got, tt.want)
			}
		})
	}
}
