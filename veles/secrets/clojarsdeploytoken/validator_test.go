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

package clojarsdeploytoken_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/clojarsdeploytoken"
)

const (
	testUsername = "saurabhb-dev"
	testToken    = "CLOJARS_cafe6346d9ef5c39890999e697f99dda6621dd03884705d341a198c6ce75"
)

// mockClojarsServer creates a mock Clojars API server for testing.
func mockClojarsServer(t *testing.T, expectedUser, expectedToken string, responseCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT request, got %s", r.Method)
		}
		expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(expectedUser+":"+expectedToken))
		if gotAuth := r.Header.Get("Authorization"); gotAuth != expectedAuth {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(responseCode)
	}))
}

func TestValidator_Validate(t *testing.T) {
	cases := []struct {
		name           string
		serverResponse int
		want           veles.ValidationStatus
	}{
		{
			name:           "valid credentials (403 success)",
			serverResponse: http.StatusForbidden,
			want:           veles.ValidationValid,
		},
		{
			name:           "invalid credentials (401 failure)",
			serverResponse: http.StatusUnauthorized,
			want:           veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := mockClojarsServer(t, testUsername, testToken, tc.serverResponse)
			defer server.Close()

			v := clojarsdeploytoken.NewValidator()
			v.HTTPC = server.Client()
			v.Endpoint = server.URL

			got, err := v.Validate(context.Background(), clojarsdeploytoken.ClojarsDeployToken{
				Username: testUsername,
				Token:    testToken,
			})

			if err != nil {
				t.Fatalf("Validate() unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidator_InvalidRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	validator := clojarsdeploytoken.NewValidator()
	validator.HTTPC = server.Client()
	validator.Endpoint = server.URL

	testCases := []struct {
		name     string
		token    string
		username string
		expected veles.ValidationStatus
		wantErr  bool
	}{
		{
			name:     "empty_token",
			token:    "",
			username: testUsername,
			expected: veles.ValidationInvalid,
		},
		{
			name:     "empty_username",
			token:    testToken,
			username: "",
			expected: veles.ValidationInvalid,
			wantErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validator.Validate(context.Background(), clojarsdeploytoken.ClojarsDeployToken{
				Token:    tc.token,
				Username: tc.username,
			})

			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error mismatch: got %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.expected {
				t.Errorf("Validate() status = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestValidator_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	v := clojarsdeploytoken.NewValidator()
	v.HTTPC = server.Client()
	v.Endpoint = server.URL

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := v.Validate(ctx, clojarsdeploytoken.ClojarsDeployToken{Username: testUsername, Token: testToken})

	if err == nil {
		t.Error("expected error for cancelled context, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("got %v, want ValidationFailed", got)
	}
}
