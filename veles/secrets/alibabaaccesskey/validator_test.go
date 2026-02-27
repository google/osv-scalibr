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

package alibabaaccesskey_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/alibabaaccesskey"
)

// mockRoundTripper intercepts requests to the real Alibaba STS endpoint
// and redirects them to our local httptest server.
type mockRoundTripper struct {
	url string
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "sts.aliyuncs.com" {
		testURL, _ := url.Parse(m.url)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockSTSServer returns an httptest.Server that simulates the Alibaba STS API
func mockSTSServer(expectedAccessID string, simulateError string) func() *httptest.Server {
	return func() *httptest.Server {
		handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// Alibaba RPC uses GET requests with query parameters
			if req.Method != http.MethodGet {
				http.Error(w, "bad method", http.StatusMethodNotAllowed)
				return
			}

			query := req.URL.Query()
			if query.Get("Action") != "GetCallerIdentity" {
				http.Error(w, "bad action", http.StatusBadRequest)
				return
			}

			// In a real scenario, the backend hashes the parameters to verify the signature.
			// For our test, we'll simulate the backend's response based on the AccessID and the simulateError flag.
			accessID := query.Get("AccessKeyId")
			if accessID != expectedAccessID {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"Code": "SignatureDoesNotMatch", "Message": "The request signature we calculated does not match the signature you provided."}`)
				return
			}

			if simulateError == "NoPermission" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"Code": "NoPermission", "Message": "You are not authorized to do this action."}`)
				return
			}

			// Success Case
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{
				"AccountId": "1234567890123456",
				"UserId": "2345678901234567",
				"Arn": "acs:ram::1234567890123456:user/test-user",
				"RequestId": "A1B2C3D4-E5F6-7890-1234-567890ABCDEF"
			}`)
		})

		return httptest.NewServer(handler)
	}
}

const (
	validAccessID = "LTAI5tHSr51ziCnfuHvwdeDw"
	validSecret   = "nyK2q4hL34mCKaEvElY253q1yAF0FL"
	badAccessID   = "LTAI_INVALID_KEY_ID"
)

func TestValidator(t *testing.T) {
	cases := []struct {
		name          string
		key           alibabaaccesskey.Credentials
		want          veles.ValidationStatus
		wantIsRam     bool
		wantPrincipal string
		server        func() *httptest.Server
	}{
		{
			name: "valid_ram_user_credentials",
			key: alibabaaccesskey.Credentials{
				AccessID: validAccessID,
				Secret:   validSecret,
			},
			want:          veles.ValidationValid,
			wantIsRam:     true,
			wantPrincipal: "test-user", // Matches the mock server ARN suffix
			server:        mockSTSServer(validAccessID, ""),
		},
		{
			name: "valid_root_credentials",
			key: alibabaaccesskey.Credentials{
				AccessID: validAccessID,
				Secret:   validSecret,
			},
			want:          veles.ValidationValid,
			wantIsRam:     false,
			wantPrincipal: "root",
			// We need a specific mock server for root to return the root ARN
			server: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = io.WriteString(w, `{"Arn": "acs:ram::1234567890123456:root"}`)
				}))
			},
		},
		{
			name: "invalid_credentials",
			key: alibabaaccesskey.Credentials{
				AccessID: badAccessID,
				Secret:   validSecret,
			},
			want:   veles.ValidationInvalid,
			server: mockSTSServer(validAccessID, ""),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := tc.server()
			defer srv.Close()

			client := &http.Client{
				Transport: &mockRoundTripper{url: srv.URL},
			}

			validator := alibabaaccesskey.NewValidator()
			validator.SetHTTPClient(client)

			// We pass a pointer (&tc.key) so Validate can update the fields
			got, err := validator.Validate(t.Context(), &tc.key)

			if err != nil {
				t.Errorf("Validate() error: %v, want nil", err)
			}
			if got != tc.want {
				t.Errorf("Validate() status = %v, want %v", got, tc.want)
			}

			// Verify the enriched metadata
			if got == veles.ValidationValid {
				if tc.key.IsRamUser != tc.wantIsRam {
					t.Errorf("IsRamUser = %v, want %v", tc.key.IsRamUser, tc.wantIsRam)
				}
				if tc.key.PrincipalName != tc.wantPrincipal {
					t.Errorf("PrincipalName = %q, want %q", tc.key.PrincipalName, tc.wantPrincipal)
				}
			}
		})
	}
}
