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

package denopat_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/denopat"
)

const validatorTestDdpPat = "ddp_qz538MNyqwfETb1ikqeqHiqA9Aa9Pv22yzmw"

const validatorTestDdoPat = "ddo_4nkT2HnlnbPpGbW5RVE7DsIyfMJ3bN3YeqZT"

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL
	if req.URL.Host == "api.deno.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockDenoServer creates a mock Deno API server for testing
func mockDenoServer(t *testing.T, expectedKey string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a GET request
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %s, expected: GET", r.Method)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Check Authorization header
		auth := r.Header.Get("Authorization")
		if auth == "" || len(auth) < 8 || auth[:7] != "Bearer " {
			t.Errorf("missing or invalid Authorization header: %s", auth)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token := auth[7:]

		// Determine an expected path based on a token prefix
		var expectedPath string
		if strings.HasPrefix(token, "ddp_") {
			expectedPath = "/user"
		} else if strings.HasPrefix(token, "ddo_") {
			expectedPath = "/organization"
		} else {
			t.Errorf("unexpected token prefix: %s", token)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// Check path
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: %s, expected: %s", r.URL.Path, expectedPath)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Check if the token is valid
		if token == expectedKey {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
}

func TestUserTokenValidator(t *testing.T) {
	cases := []struct {
		name string
		Pat  string
		want veles.ValidationStatus
	}{
		{
			name: "valid ddp",
			Pat:  validatorTestDdpPat,
			want: veles.ValidationValid,
		},
		{
			name: "invalid ddp",
			Pat:  "ddp_invalid",
			want: veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Determine expected key for mock server
			expectedKey := "some_invalid_key"
			if tc.want == veles.ValidationValid {
				expectedKey = tc.Pat
			}

			// Create a mock server
			server := mockDenoServer(t, expectedKey)
			defer server.Close()

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create a validator with a mock client
			validator := denopat.NewUserTokenValidator(
				denopat.WithClient(client),
			)

			// Create a test pat
			pat := denopat.DenoUserPAT{Pat: tc.Pat}

			// Test validation
			got, err := validator.Validate(context.Background(), pat)

			if !cmp.Equal(err, nil, cmpopts.EquateErrors()) {
				t.Fatalf("plugin.Validate(%v) got error: %v\n", pat, err)
			}

			// Check validation status
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOrgTokenValidator(t *testing.T) {
	cases := []struct {
		name string
		Pat  string
		want veles.ValidationStatus
	}{
		{
			name: "valid ddo",
			Pat:  validatorTestDdoPat,
			want: veles.ValidationValid,
		},
		{
			name: "invalid ddo",
			Pat:  "ddo_invalid",
			want: veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Determine expected key for mock server
			expectedKey := "some_invalid_key"
			if tc.want == veles.ValidationValid {
				expectedKey = tc.Pat
			}

			// Create a mock server
			server := mockDenoServer(t, expectedKey)
			defer server.Close()

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create a validator with a mock client
			validator := denopat.NewOrgTokenValidator(
				denopat.WithClient(client),
			)

			// Create a test pat
			pat := denopat.DenoOrgPAT{Pat: tc.Pat}

			// Test validation
			got, err := validator.Validate(context.Background(), pat)

			if !cmp.Equal(err, nil, cmpopts.EquateErrors()) {
				t.Fatalf("plugin.Validate(%v) got error: %v\n", pat, err)
			}

			// Check validation status
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}
func TestUserTokenValidator_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := denopat.NewUserTokenValidator(
		denopat.WithClient(client),
	)

	// Create a test pat
	pat := denopat.DenoUserPAT{Pat: validatorTestDdpPat}

	// Create context with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// Test validation with cancelled context
	got, err := validator.Validate(ctx, pat)

	if err == nil {
		t.Errorf("Validate() expected error due to context cancellation, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}

func TestOrgTokenValidator_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := denopat.NewOrgTokenValidator(
		denopat.WithClient(client),
	)

	// Create a test pat
	pat := denopat.DenoOrgPAT{Pat: validatorTestDdoPat}

	// Create context with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// Test validation with cancelled context
	got, err := validator.Validate(ctx, pat)

	if err == nil {
		t.Errorf("Validate() expected error due to context cancellation, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}

func TestUserTokenValidator_InvalidRequest(t *testing.T) {
	// Create a mock server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := denopat.NewUserTokenValidator(
		denopat.WithClient(client),
	)

	testCases := []struct {
		name     string
		Pat      string
		expected veles.ValidationStatus
	}{
		{
			name:     "empty_key",
			Pat:      "",
			expected: veles.ValidationInvalid,
		},
		{
			name:     "invalid_key_format",
			Pat:      "invalid-key-format",
			expected: veles.ValidationInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pat := denopat.DenoUserPAT{Pat: tc.Pat}

			got, err := validator.Validate(context.Background(), pat)

			if err != nil {
				t.Errorf("Validate() unexpected error for %s: %v", tc.name, err)
			}
			if got != tc.expected {
				t.Errorf("Validate() = %v, want %v for %s", got, tc.expected, tc.name)
			}
		})
	}
}

func TestOrgTokenValidator_InvalidRequest(t *testing.T) {
	// Create a mock server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := denopat.NewOrgTokenValidator(
		denopat.WithClient(client),
	)

	testCases := []struct {
		name     string
		Pat      string
		expected veles.ValidationStatus
	}{
		{
			name:     "empty_key",
			Pat:      "",
			expected: veles.ValidationInvalid,
		},
		{
			name:     "invalid_key_format",
			Pat:      "invalid-key-format",
			expected: veles.ValidationInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pat := denopat.DenoOrgPAT{Pat: tc.Pat}

			got, err := validator.Validate(context.Background(), pat)

			if err != nil {
				t.Errorf("Validate() unexpected error for %s: %v", tc.name, err)
			}
			if got != tc.expected {
				t.Errorf("Validate() = %v, want %v for %s", got, tc.expected, tc.name)
			}
		})
	}
}
