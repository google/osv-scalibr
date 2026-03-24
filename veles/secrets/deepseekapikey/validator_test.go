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

package deepseekapikey_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/deepseekapikey"
)

const validatorTestKey = "sk-15ac903f2e481u3d4f9g2u3ia8e2b73n"

// mockDeepSeekServer creates a mock DeepSeek API server for testing.
func mockDeepSeekServer(t *testing.T, expectedKey string, statusCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/chat/completions" {
			t.Errorf("unexpected request: %s %s, expected: POST /chat/completions",
				r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}

		expectedAuth := "Bearer " + expectedKey
		if auth := r.Header.Get("Authorization"); auth != expectedAuth {
			t.Errorf("Authorization = %q, want %q", auth, expectedAuth)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		want       veles.ValidationStatus
		wantErr    error
	}{
		{
			name:       "valid_key",
			statusCode: http.StatusOK,
			want:       veles.ValidationValid,
		},
		{
			name:       "invalid_key_unauthorized",
			statusCode: http.StatusUnauthorized,
			want:       veles.ValidationInvalid,
		},
		{
			name:       "rate_limited_but_likely_valid",
			statusCode: http.StatusTooManyRequests,
			want:       veles.ValidationValid,
		},
		{
			name:       "payment_required_but_likely_valid",
			statusCode: http.StatusPaymentRequired,
			want:       veles.ValidationValid,
		},
		{
			name:       "forbidden_but_likely_valid",
			statusCode: http.StatusForbidden,
			want:       veles.ValidationValid,
		},
		{
			name:       "server_error",
			statusCode: http.StatusInternalServerError,
			want:       veles.ValidationFailed,
			wantErr:    cmpopts.AnyError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := mockDeepSeekServer(t, validatorTestKey, tc.statusCode)
			defer server.Close()

			validator := deepseekapikey.NewAPIValidator()
			validator.HTTPC = server.Client()
			validator.Endpoint = server.URL + "/chat/completions"

			key := deepseekapikey.APIKey{Key: validatorTestKey}

			got, err := validator.Validate(t.Context(), key)

			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
			}

			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}
