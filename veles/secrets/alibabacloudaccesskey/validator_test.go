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

package alibabacloudaccesskey_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/alibabacloudaccesskey"
)

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

func mockSTSServer(validAccessKeyID string) func() *httptest.Server {
	return func() *httptest.Server {
		handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}

			action := req.URL.Query().Get("Action")
			if action != "GetCallerIdentity" {
				http.Error(w, "unknown action", http.StatusBadRequest)
				return
			}

			accessKeyID := req.URL.Query().Get("AccessKeyId")
			if accessKeyID != validAccessKeyID {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"RequestId":"test","Code":"InvalidAccessKeyId.NotFound","Message":"Specified access key is not found."}`)
				return
			}

			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{
				"RequestId": "test-request-id",
				"AccountId": "1234567890",
				"IdentityType": "RAMUser",
				"PrincipalId": "214260371570839990",
				"UserId": "214260371570839990",
				"Arn": "acs:ram::1234567890:user/test-user"
			}`)
		})
		return httptest.NewServer(handler)
	}
}

func mockSTSServerSignatureMismatch() func() *httptest.Server {
	return func() *httptest.Server {
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"RequestId":"test","Code":"SignatureDoesNotMatch","Message":"Specified signature is not matched."}`)
		})
		return httptest.NewServer(handler)
	}
}

func mockSTSServerForbidden() func() *httptest.Server {
	return func() *httptest.Server {
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"RequestId":"test","Code":"Forbidden.AccessDenied","Message":"User is not authorized to perform sts:GetCallerIdentity."}`)
		})
		return httptest.NewServer(handler)
	}
}

const (
	exampleAccessKeyID     = "LTAI5tB9hcbFSuN7nYnTqXkZ"
	exampleAccessKeySecret = "zF4g1bH8kR2mN5pT7vW9xY3aQ6dJ8n"
)

func TestValidator(t *testing.T) {
	cases := []struct {
		name   string
		key    alibabacloudaccesskey.Credentials
		want   veles.ValidationStatus
		server func() *httptest.Server
	}{
		{
			name: "valid_credentials",
			key: alibabacloudaccesskey.Credentials{
				AccessKeyID:     exampleAccessKeyID,
				AccessKeySecret: exampleAccessKeySecret,
			},
			want:   veles.ValidationValid,
			server: mockSTSServer(exampleAccessKeyID),
		},
		{
			name: "invalid_access_key_id",
			key: alibabacloudaccesskey.Credentials{
				AccessKeyID:     "LTAI5tInvalidKeyIDXXXXXXX",
				AccessKeySecret: exampleAccessKeySecret,
			},
			want:   veles.ValidationInvalid,
			server: mockSTSServer(exampleAccessKeyID),
		},
		{
			name: "signature_mismatch",
			key: alibabacloudaccesskey.Credentials{
				AccessKeyID:     exampleAccessKeyID,
				AccessKeySecret: "wrongsecretwrongsecretwrongse",
			},
			want:   veles.ValidationInvalid,
			server: mockSTSServerSignatureMismatch(),
		},
		{
			name: "forbidden_but_authenticated",
			key: alibabacloudaccesskey.Credentials{
				AccessKeyID:     exampleAccessKeyID,
				AccessKeySecret: exampleAccessKeySecret,
			},
			want:   veles.ValidationValid,
			server: mockSTSServerForbidden(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := tc.server()
			defer srv.Close()

			client := &http.Client{
				Transport: &mockRoundTripper{url: srv.URL},
			}

			validator := alibabacloudaccesskey.NewValidator()
			validator.SetHTTPClient(client)

			got, err := validator.Validate(t.Context(), tc.key)
			if err != nil {
				t.Errorf("Validate() error: %v, want nil", err)
			}
			if got != tc.want {
				t.Errorf("Validate() = %q, want %q", got, tc.want)
			}
		})
	}
}
