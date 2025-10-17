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

package hcp_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
	"github.com/google/osv-scalibr/veles/secrets/hcp"
)

const (
	validatorTestClientID     = "53au9oDSqR8SBzIy6QJASHnyC1SMQxE3"
	validatorTestClientSecret = "x2Nyv_C0NiJLEheDO5LuAmJj7v_SrY5cpWWCi38WCcmohTFzAl48zoiEFivQBU2n"
	validatorTestAccessToken  = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGguaWRwLmhhc2hpY29ycC5jb20vIiwiYXVkIjpbImh0dHBzOi8vYXBpLmhhc2hpY29ycC5jbG91ZCJdLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMiLCJodHRwczovL2Nsb3VkLmhhc2hpY29ycC5jb20vcHJpbmNpcGFsLXR5cGUiOiJzZXJ2aWNlIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

// mockTokenServer returns a server that emulates the HCP token endpoint behavior.
func mockTokenServer(t *testing.T, expectID, expectSecret string, success bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/oauth2/token" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			t.Errorf("unexpected content-type: %q", ct)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("unable to read request body: %v", err)
		}
		_ = r.Body.Close()
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("unable to parse form: %v", err)
		}
		if vals.Get("grant_type") != "client_credentials" {
			t.Errorf("unexpected grant_type: %q", vals.Get("grant_type"))
		}

		if success && (vals.Get("client_id") != expectID || vals.Get("client_secret") != expectSecret) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		if !success {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": validatorTestAccessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
}

func TestClientCredentialsValidator(t *testing.T) {
	cases := []struct {
		name   string
		id     string
		secret string
		ok     bool
		want   veles.ValidationStatus
	}{
		{name: "valid_pair", id: validatorTestClientID, secret: validatorTestClientSecret, ok: true, want: veles.ValidationValid},
		{name: "invalid_pair", id: validatorTestClientID, secret: "wrong_secret", ok: false, want: veles.ValidationInvalid},
		{name: "missing_id", id: "", secret: validatorTestClientSecret, ok: true, want: veles.ValidationInvalid},
		{name: "missing_secret", id: validatorTestClientID, secret: "", ok: true, want: veles.ValidationInvalid},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := mockTokenServer(t, validatorTestClientID, validatorTestClientSecret, tc.ok)
			defer srv.Close()

			v := hcp.NewClientCredentialsValidator(
				simplevalidate.WithClient[hcp.ClientCredentials](http.DefaultClient),
				simplevalidate.WithEndpoint[hcp.ClientCredentials](srv.URL+"/oauth2/token"),
			)

			got, err := v.Validate(context.Background(), hcp.ClientCredentials{ClientID: tc.id, ClientSecret: tc.secret})
			if err != nil && (tc.want == veles.ValidationValid || tc.want == veles.ValidationInvalid || tc.want == veles.ValidationUnsupported) {
				t.Fatalf("Validate() unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClientCredentialsValidator_Errors(t *testing.T) {
	t.Run("connection error returns failed", func(t *testing.T) {
		// Start and immediately close to simulate server down
		srv := mockTokenServer(t, validatorTestClientID, validatorTestClientSecret, true)
		base := srv.URL
		srv.Close()

		v := hcp.NewClientCredentialsValidator(
			simplevalidate.WithClient[hcp.ClientCredentials](http.DefaultClient),
			simplevalidate.WithEndpoint[hcp.ClientCredentials](base+"/oauth2/token"),
		)

		got, err := v.Validate(context.Background(), hcp.ClientCredentials{ClientID: validatorTestClientID, ClientSecret: validatorTestClientSecret})
		if err == nil {
			t.Fatalf("expected error due to connection failure, got nil")
		}
		if got != veles.ValidationFailed {
			t.Errorf("Status = %v, want %v", got, veles.ValidationFailed)
		}
	})

	t.Run("server down returns failed", func(t *testing.T) {
		// Create a server that always returns 500 on /oauth2/token
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/oauth2/token" {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"internal"}`))
		}))
		defer srv.Close()

		v := hcp.NewClientCredentialsValidator(
			simplevalidate.WithClient[hcp.ClientCredentials](http.DefaultClient),
			simplevalidate.WithEndpoint[hcp.ClientCredentials](srv.URL+"/oauth2/token"),
		)

		got, err := v.Validate(context.Background(), hcp.ClientCredentials{ClientID: validatorTestClientID, ClientSecret: validatorTestClientSecret})
		if err == nil {
			t.Fatalf("expected error for 500 response, got nil")
		}
		if got != veles.ValidationFailed {
			t.Errorf("Status = %v, want %v", got, veles.ValidationFailed)
		}
	})
}

// mockAPIBaseServer returns a server that emulates a minimal HCP API base for token validation.
func mockAPIBaseServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/iam/2019-12-10/caller-identity" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(status)
	}))
}

func TestAccessTokenValidator(t *testing.T) {
	cases := []struct {
		name  string
		httpS int
		want  veles.ValidationStatus
	}{
		{name: "ok_200", httpS: http.StatusOK, want: veles.ValidationValid},
		{name: "unauthorized_401", httpS: http.StatusUnauthorized, want: veles.ValidationInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := mockAPIBaseServer(t, tc.httpS)
			defer srv.Close()

			v := hcp.NewAccessTokenValidator(
				simplevalidate.WithClient[hcp.AccessToken](http.DefaultClient),
				hcp.WithAPIBase(srv.URL),
			)

			got, err := v.Validate(context.Background(), hcp.AccessToken{Token: validatorTestAccessToken})
			if !cmp.Equal(err, nil, cmpopts.EquateErrors()) {
				t.Fatalf("Validate() unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAccessTokenValidator_Errors(t *testing.T) {
	t.Run("server down returns failed", func(t *testing.T) {
		// Start and immediately close to simulate server down
		srv := mockAPIBaseServer(t, http.StatusOK)
		base := srv.URL
		srv.Close()

		v := hcp.NewAccessTokenValidator(
			simplevalidate.WithClient[hcp.AccessToken](http.DefaultClient),
			hcp.WithAPIBase(base),
		)
		got, err := v.Validate(context.Background(), hcp.AccessToken{Token: validatorTestAccessToken})
		if err == nil {
			t.Fatalf("expected error due to connection failure, got nil")
		}
		if got != veles.ValidationFailed {
			t.Errorf("Status = %v, want %v", got, veles.ValidationFailed)
		}
	})

	t.Run("server error returns failed", func(t *testing.T) {
		srv := mockAPIBaseServer(t, http.StatusInternalServerError)
		defer srv.Close()

		v := hcp.NewAccessTokenValidator(
			simplevalidate.WithClient[hcp.AccessToken](http.DefaultClient),
			hcp.WithAPIBase(srv.URL),
		)
		got, err := v.Validate(context.Background(), hcp.AccessToken{Token: validatorTestAccessToken})
		if err == nil {
			t.Fatalf("expected error for 500 response, got nil")
		}
		if got != veles.ValidationFailed {
			t.Errorf("Status = %v, want %v", got, veles.ValidationFailed)
		}
	})
}
