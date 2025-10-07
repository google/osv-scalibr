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

// Package mockgithub contains a mock implementation of the Github APIss
package mockgithub

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// Server creates a mock Github API server for testing
func Server(t *testing.T, path string, code int, keys ...string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a GET request to the expected endpoint
		if r.Method != http.MethodGet || r.URL.Path != path {
			t.Errorf("unexpected request: %s %s, expected: GET %s", r.Method, r.URL.Path, path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// if the user specified an hard-coded return code, like 500 just return it
		if code != http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			return
		}

		// Check Authorization header
		authHeader := r.Header.Get("Authorization")

		for _, k := range keys {
			if authHeader == "Bearer "+k {
				// return ok on match
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
	}))
}

type mockTransport struct {
	roundTrip func(req *http.Request) (*http.Response, error)
}

// RoundTrip allows mockTransport to satisfy the http.RoundTripper interface.
func (m mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTrip(req)
}

// Transport returns a mock http.RoundTripper which redirects traffic to the specified Github *httptest.Server
func Transport(github *httptest.Server) http.RoundTripper {
	return mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "api.github.com" {
				testURL, _ := url.Parse(github.URL)
				req.URL.Scheme = testURL.Scheme
				req.URL.Host = testURL.Host
			}
			return http.DefaultTransport.RoundTrip(req)
		},
	}
}
