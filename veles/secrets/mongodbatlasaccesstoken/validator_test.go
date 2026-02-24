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

package mongodbatlasaccesstoken_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/mongodbatlasaccesstoken"
)

const validAccessToken = "eyJraWQiOiJ0ZXN0IiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjF9.dGVzdA"

// mockAtlasTransport redirects requests to the test server.
type mockAtlasTransport struct {
	testServer *httptest.Server
}

func (m *mockAtlasTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "cloud.mongodb.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockAtlasAccessTokenServer creates a mock MongoDB Atlas API server for access token validation.
func mockAtlasAccessTokenServer(t *testing.T, expectedToken string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/atlas/v2/clusters" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer "+expectedToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
}

func TestAccessTokenValidator(t *testing.T) {
	cases := []struct {
		name        string
		accessToken string
		want        veles.ValidationStatus
	}{
		{
			name:        "valid access token",
			accessToken: validAccessToken,
			want:        veles.ValidationValid,
		},
		{
			name:        "invalid access token",
			accessToken: "invalid_token",
			want:        veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := mockAtlasAccessTokenServer(t, validAccessToken)
			defer server.Close()

			client := &http.Client{
				Transport: &mockAtlasTransport{testServer: server},
			}

			validator := mongodbatlasaccesstoken.NewAccessTokenValidator()
			validator.HTTPC = client

			token := mongodbatlasaccesstoken.MongoDBAtlasAccessToken{Token: tc.accessToken}
			got, err := validator.Validate(t.Context(), token)

			if !cmp.Equal(err, nil, cmpopts.EquateErrors()) {
				t.Fatalf("Validate(%v) got error: %v", token, err)
			}
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAccessTokenValidator_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &http.Client{
		Transport: &mockAtlasTransport{testServer: server},
	}

	validator := mongodbatlasaccesstoken.NewAccessTokenValidator()
	validator.HTTPC = client

	token := mongodbatlasaccesstoken.MongoDBAtlasAccessToken{Token: validAccessToken}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	got, err := validator.Validate(ctx, token)
	if err == nil {
		t.Errorf("Validate() expected error due to context cancellation, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}
