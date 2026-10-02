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

package qwenpat_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/qwenpat"
)

const validatorTestQwenPat = "sk-[A-Za-z0-9]{32}"

// regionalHosts are the hosts of the DashScope regional domains, in the order
// the validator queries them.
var regionalHosts = []string{
	"dashscope-intl.aliyuncs.com",
	"dashscope-us.aliyuncs.com",
	"cn-hongkong.dashscope.aliyuncs.com",
	"dashscope.aliyuncs.com",
}

// mockTransport redirects requests to the test server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the original URL with our test server URL. Every DashScope
	// regional domain has to be redirected, not only the international one.
	if strings.HasSuffix(req.URL.Host, ".aliyuncs.com") {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// hostStatusTransport answers every regional DashScope endpoint without any
// network access and records the order in which the endpoints were queried.
type hostStatusTransport struct {
	// statuses maps a DashScope host to the status code it replies with.
	// Hosts missing from the map reply 404.
	statuses map[string]int
	// queried records the hosts in the order they were requested.
	queried []string
}

func (t *hostStatusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.queried = append(t.queried, req.URL.Host)
	status := http.StatusNotFound
	if s, ok := t.statuses[req.URL.Host]; ok {
		status = s
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// mockDashScopeServer creates a mock DashScope API server for testing
func mockDashScopeServer(t *testing.T, expectedKey string) *httptest.Server {
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

		// Check path
		if r.URL.Path != "/compatible-mode/v1/models" {
			t.Errorf("unexpected path: %s, expected: /compatible-mode/v1/models", r.URL.Path)
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

func TestValidator(t *testing.T) {
	cases := []struct {
		name string
		Pat  string
		want veles.ValidationStatus
	}{
		{
			name: "valid key",
			Pat:  validatorTestQwenPat,
			want: veles.ValidationValid,
		},
		{
			name: "invalid key",
			Pat:  "key_invalid",
			want: veles.ValidationInvalid,
		},
		{
			name: "unknown prefix",
			Pat:  "unknown",
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
			server := mockDashScopeServer(t, expectedKey)
			defer server.Close()

			// Create a client with custom transport
			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			// Create a validator with a mock client
			validator := qwenpat.NewValidator()
			validator.HTTPC = client

			// Create a test pat
			pat := qwenpat.QwenPAT{Pat: tc.Pat}

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

// TestValidator_RegionalEndpoints checks that every DashScope regional
// endpoint is queried before a key is classified as invalid, because API
// keys are bound to the region they were created in.
func TestValidator_RegionalEndpoints(t *testing.T) {
	unauthorized := http.StatusUnauthorized
	cases := []struct {
		name        string
		statuses    map[string]int
		want        veles.ValidationStatus
		wantQueried []string
	}{
		{
			// The key was created in the US, so only the second endpoint
			// accepts it: validation has to succeed instead of stopping at
			// the first 401.
			name: "accepted by a non-first endpoint",
			statuses: map[string]int{
				"dashscope-intl.aliyuncs.com":        unauthorized,
				"dashscope-us.aliyuncs.com":          http.StatusOK,
				"cn-hongkong.dashscope.aliyuncs.com": unauthorized,
				"dashscope.aliyuncs.com":             unauthorized,
			},
			want: veles.ValidationValid,
			// Validation stops as soon as an endpoint accepts the key.
			wantQueried: regionalHosts[:2],
		},
		{
			// No endpoint accepts the key: all four have to be tried before
			// the key is reported as invalid.
			name: "rejected by every endpoint",
			statuses: map[string]int{
				"dashscope-intl.aliyuncs.com":        unauthorized,
				"dashscope-us.aliyuncs.com":          unauthorized,
				"cn-hongkong.dashscope.aliyuncs.com": unauthorized,
				"dashscope.aliyuncs.com":             unauthorized,
			},
			want:        veles.ValidationInvalid,
			wantQueried: regionalHosts,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			transport := &hostStatusTransport{statuses: tc.statuses}

			validator := qwenpat.NewValidator()
			validator.HTTPC = &http.Client{Transport: transport}

			got, err := validator.Validate(context.Background(), qwenpat.QwenPAT{Pat: validatorTestQwenPat})
			if err != nil {
				t.Fatalf("Validate() error: %v, want nil", err)
			}
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
			if diff := cmp.Diff(tc.wantQueried, transport.queried); diff != "" {
				t.Errorf("queried endpoints diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestValidator_ContextCancellation(t *testing.T) {
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

	validator := qwenpat.NewValidator()
	validator.HTTPC = client

	// Create a test pat
	pat := qwenpat.QwenPAT{Pat: validatorTestQwenPat}

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

func TestValidator_InvalidRequest(t *testing.T) {
	// Create a mock server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	// Create a client with custom transport
	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := qwenpat.NewValidator()
	validator.HTTPC = client

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
			pat := qwenpat.QwenPAT{Pat: tc.Pat}

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
