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

package gcpoauth2access_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gcpoauth2access"
)

const (
	endpoint = "https://www.googleapis.com/oauth2/v3/tokeninfo"
)

type mockRoundTripper struct {
	want *http.Request
	resp *http.Response
	err  error
	t    *testing.T
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Set empty header and host for convenience.
	// We care if these fields are drastically different, but not if they are nil vs empty.
	if m.want.Header == nil {
		m.want.Header = make(http.Header)
	}
	if m.want.Host == "" {
		m.want.Host = req.Host
	}
	opts := []cmp.Option{
		cmpopts.IgnoreUnexported(http.Request{}),
		cmpopts.IgnoreFields(http.Request{}, "Proto", "ProtoMajor", "ProtoMinor"),
	}
	if diff := cmp.Diff(m.want, req, opts...); diff != "" {
		m.t.Fatalf("Received unexpected request (-want +got):\n%s", diff)
	}
	return m.resp, m.err
}

// response represents the response from Google's OAuth2 token endpoint.
// https://developers.google.com/identity/protocols/oauth2
type response struct {
	// Expiry is the expiration time of the token in Unix time.
	Expiry string `json:"exp"`
	// ExpiresIn is the number of seconds until the token expires.
	ExpiresIn string `json:"expires_in"`
	// Scope is a space-delimited list that identify the resources that your application could access
	// https://developers.google.com/identity/protocols/oauth2/scopes
	Scope string `json:"scope"`
}

func TestValidator_Validate(t *testing.T) {
	realTokenURL := mustURLWithParams(t, endpoint, map[string]string{"access_token": realToken})

	tests := []struct {
		name         string
		roundTripper *mockRoundTripper
		token        gcpoauth2access.Token
		want         veles.ValidationStatus
		wantErr      bool
	}{
		{
			name: "empty",
			token: gcpoauth2access.Token{
				Token: "",
			},
			want:    veles.ValidationFailed,
			wantErr: true,
		},
		{
			name: "request_error",
			roundTripper: &mockRoundTripper{
				want: &http.Request{
					Method: http.MethodGet,
					URL:    realTokenURL,
				},
				err: errors.New("request error"),
			},
			token: gcpoauth2access.Token{
				Token: realToken,
			},
			want:    veles.ValidationFailed,
			wantErr: true,
		},
		{
			name: "bad_request",
			roundTripper: &mockRoundTripper{
				want: &http.Request{
					Method: http.MethodGet,
					URL:    realTokenURL,
				},
				resp: &http.Response{
					StatusCode: http.StatusBadRequest,
				},
			},
			token: gcpoauth2access.Token{
				Token: realToken,
			},
			want: veles.ValidationInvalid,
		},
		{
			name: "server_error",
			roundTripper: &mockRoundTripper{
				want: &http.Request{
					Method: http.MethodGet,
					URL:    realTokenURL,
				},
				resp: &http.Response{
					StatusCode: http.StatusInternalServerError,
				},
			},
			token: gcpoauth2access.Token{
				Token: realToken,
			},
			want:    veles.ValidationFailed,
			wantErr: true,
		},
		{
			name: "unexpected_json",
			roundTripper: &mockRoundTripper{
				want: &http.Request{
					Method: http.MethodGet,
					URL:    realTokenURL,
				},
				resp: &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("unexpected json")),
				},
			},
			token: gcpoauth2access.Token{
				Token: realToken,
			},
			want:    veles.ValidationFailed,
			wantErr: true,
		},
		{
			name: "valid_token",
			roundTripper: &mockRoundTripper{
				want: &http.Request{
					Method: http.MethodGet,
					URL:    realTokenURL,
				},
				resp: &http.Response{
					StatusCode: http.StatusOK,
					Body: mustJSONReadCloser(t, response{
						Expiry:    "1743465600",
						ExpiresIn: "3600",
						Scope:     "https://www.googleapis.com/auth/cloud-platform",
					}),
				},
			},
			token: gcpoauth2access.Token{
				Token: realToken,
			},
			want: veles.ValidationValid,
		},
		{
			name: "expired_based_on_expires_in",
			roundTripper: &mockRoundTripper{
				want: &http.Request{
					Method: http.MethodGet,
					URL:    realTokenURL,
				},
				resp: &http.Response{
					StatusCode: http.StatusOK,
					Body: mustJSONReadCloser(t, response{
						Expiry:    strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10),
						ExpiresIn: "0",
						Scope:     "https://www.googleapis.com/auth/cloud-platform",
					}),
				},
			},
			token: gcpoauth2access.Token{
				Token: realToken,
			},
			want: veles.ValidationInvalid,
		},
		{
			name: "expired_based_on_expiry",
			roundTripper: &mockRoundTripper{
				want: &http.Request{
					Method: http.MethodGet,
					URL:    realTokenURL,
				},
				resp: &http.Response{
					StatusCode: http.StatusOK,
					Body: mustJSONReadCloser(t, response{
						Expiry:    strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10),
						ExpiresIn: "unparsable",
						Scope:     "https://www.googleapis.com/auth/cloud-platform",
					}),
				},
			},
			token: gcpoauth2access.Token{
				Token: realToken,
			},
			want: veles.ValidationInvalid,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.roundTripper != nil {
				tc.roundTripper.t = t
			}
			v := gcpoauth2access.NewValidator()
			v.HTTPC = &http.Client{Transport: tc.roundTripper}

			got, err := v.Validate(t.Context(), tc.token)
			if tc.wantErr {
				if err == nil {
					t.Errorf("Validate() error: %v, want error: %t", err, tc.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() error: %v, want nil", err)
				}
			}
			if got != tc.want {
				t.Errorf("Validate() = %q, want %q", got, tc.want)
			}
		})
	}
}

func mustURLWithParams(t *testing.T, endpoint string, params map[string]string) *url.URL {
	t.Helper()
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		t.Fatalf("Failed to parse endpoint: %v", err)
	}

	paramsURL := url.Values{}
	for k, v := range params {
		paramsURL.Set(k, v)
	}
	endpointURL.RawQuery = paramsURL.Encode()
	return endpointURL
}

// mustJSONReadCloser marshals a struct into JSON, converts it to an io.Reader,
// and wraps it in an io.ReadCloser, failing the test if marshaling fails.
func mustJSONReadCloser(t *testing.T, data any) io.ReadCloser {
	t.Helper()
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Failed to marshal struct to JSON: %v", err)
	}
	return io.NopCloser(strings.NewReader(string(b)))
}
