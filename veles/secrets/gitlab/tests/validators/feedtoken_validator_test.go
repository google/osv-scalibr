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

package gitlab_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gitlab"
)

const validatorTestFeedToken = "glft-dVtnfc2zBubZH1saymzz"

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	testURL, _ := url.Parse(m.testServer.URL)
	req.URL.Scheme = testURL.Scheme
	req.URL.Host = testURL.Host
	return http.DefaultTransport.RoundTrip(req)
}

// mockGitlabFeedServer creates a mock GitLab server for testing feed tokens
func mockGitlabFeedServer(t *testing.T, expectedToken string, serverResponseCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a GET request to the expected endpoint
		if r.Method != http.MethodGet || r.URL.Path != "/dashboard/projects.atom" {
			t.Errorf("unexpected request: %s %s, expected: GET /dashboard/projects.atom", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check feed_token query parameter
		feedToken := r.URL.Query().Get("feed_token")
		if len(expectedToken) > 0 && feedToken != expectedToken {
			w.Header().Set("Content-Type", "application/atom+xml")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Set response
		w.Header().Set("Content-Type", "application/atom+xml")
		w.WriteHeader(serverResponseCode)
		if serverResponseCode == http.StatusOK {
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Dashboard</title>
</feed>`))
		}
	}))
}

func TestFeedTokenValidator(t *testing.T) {
	cases := []struct {
		name               string
		token              string
		hostname           string
		serverExpectedKey  string
		serverResponseCode int
		want               veles.ValidationStatus
		expectError        bool
	}{
		{
			name:               "valid_feed_token",
			token:              validatorTestFeedToken,
			hostname:           "gitlab.com",
			serverExpectedKey:  validatorTestFeedToken,
			serverResponseCode: http.StatusOK,
			want:               veles.ValidationValid,
		},
		{
			name:               "invalid_feed_token_unauthorized",
			token:              "glft-invalid",
			hostname:           "gitlab.com",
			serverExpectedKey:  validatorTestFeedToken,
			serverResponseCode: http.StatusUnauthorized,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "invalid_feed_token_forbidden",
			token:              "glft-invalid",
			hostname:           "gitlab.com",
			serverExpectedKey:  validatorTestFeedToken,
			serverResponseCode: http.StatusForbidden,
			want:               veles.ValidationInvalid,
		},
		{
			name:               "server_error",
			token:              validatorTestFeedToken,
			hostname:           "gitlab.com",
			serverResponseCode: http.StatusInternalServerError,
			want:               veles.ValidationFailed,
			expectError:        true,
		},
		{
			name:               "not_found",
			token:              validatorTestFeedToken,
			hostname:           "gitlab.com",
			serverResponseCode: http.StatusNotFound,
			want:               veles.ValidationFailed,
			expectError:        true,
		},
		{
			name:               "valid_feed_token_custom_hostname",
			token:              validatorTestFeedToken,
			hostname:           "gitlab.example.com",
			serverExpectedKey:  validatorTestFeedToken,
			serverResponseCode: http.StatusOK,
			want:               veles.ValidationValid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock server
			server := mockGitlabFeedServer(t, tc.serverExpectedKey, tc.serverResponseCode)
			defer server.Close()

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create a validator with a mock client
			validator := gitlab.NewFeedTokenValidator()
			validator.HTTPC = client

			// Create a test feed token
			feedToken := gitlab.FeedToken{
				Token:    tc.token,
				Hostname: tc.hostname,
			}

			// Test validation
			got, err := validator.Validate(t.Context(), feedToken)

			// Check error expectation
			if tc.expectError {
				if err == nil {
					t.Errorf("Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}

			// Check validation status
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFeedTokenValidator_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := gitlab.NewFeedTokenValidator()
	validator.HTTPC = client

	feedToken := gitlab.FeedToken{
		Token:    validatorTestFeedToken,
		Hostname: "gitlab.com",
	}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Test validation with cancelled context
	got, err := validator.Validate(ctx, feedToken)

	if err == nil {
		t.Errorf("Validate() expected error due to context cancellation, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}
