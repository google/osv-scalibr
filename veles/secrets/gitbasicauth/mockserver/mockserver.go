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

// Package mockserver contains a mock implementation of a git server for testing purposes.
package mockserver

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type Transport struct {
	URL string
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	newURL, err := url.Parse(t.URL)
	if err != nil {
		return nil, err
	}
	req.URL.Scheme = newURL.Scheme
	req.URL.Host = newURL.Host
	return http.DefaultTransport.RoundTrip(req)
}

func GitHandler(t *testing.T, status int) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("r.Method = %s, want %s", r.Method, http.MethodGet)
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic") {
			t.Errorf("should use basic auth")
		}
		w.WriteHeader(status)
	}
}
