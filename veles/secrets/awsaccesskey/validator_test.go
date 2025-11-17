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

package awsaccesskey_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/awsaccesskey"
)

type fakeSigner struct{}

func (n fakeSigner) Sign(r *http.Request, accessID string, secret string) error {
	r.Header.Set("Authorization", "Signature="+accessID+":"+secret)
	return nil
}

type mockRoundTripper struct {
	url string
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "sts.us-east-1.amazonaws.com" {
		testURL, _ := url.Parse(m.url)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockSTSServer returns an httptest.Server that simulates the AWS STS server
func mockSTSServer(signature string) func() *httptest.Server {
	return func() *httptest.Server {
		handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// Only handle GetCallerIdentity (POST /)
			if req.Method != http.MethodPost || req.URL.Path != "/" || req.Body == nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			body, _ := io.ReadAll(req.Body)
			if !bytes.HasPrefix(body, []byte("Action=GetCallerIdentity")) {
				http.Error(w, "bad method", http.StatusNotFound)
			}

			if !strings.Contains(req.Header.Get("Authorization"), signature) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
				  <Error>
				    <Type>Sender</Type>
				    <Code>SignatureDoesNotMatch</Code>
				    <Message>The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.</Message>
				  </Error>
				  <RequestId>f7a4e6b1-9d2c-4f80-8a7e-3c5d9f1b0e2b</RequestId>
				</ErrorResponse>`)
				return
			}

			_, _ = io.WriteString(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
			  <GetCallerIdentityResult>
			    <Arn>***</Arn>
			    <UserId>***</UserId>
			    <Account>***</Account>
			  </GetCallerIdentityResult>
			  <ResponseMetadata>
			    <RequestId>f7a4e6b1-9d2c-4f80-8a7e-3c5d9f1b0e2a</RequestId>
			  </ResponseMetadata>
			</GetCallerIdentityResponse>`)
			w.WriteHeader(http.StatusOK)
		})

		return httptest.NewServer(handler)
	}
}

const (
	exampleAccessID  = "AIKAerkjf4f034"
	correctSecret    = "testsecret"
	badSecret        = "badSecret"
	correctSignature = exampleAccessID + ":" + correctSecret
)

func TestValidator(t *testing.T) {
	// Set up fake "GCP metadata" HTTP server.
	cases := []struct {
		name   string
		key    awsaccesskey.Credentials
		want   veles.ValidationStatus
		server func() *httptest.Server
	}{
		{
			name: "correct_secret",
			key: awsaccesskey.Credentials{
				AccessID: exampleAccessID,
				Secret:   correctSecret,
			},
			want:   veles.ValidationValid,
			server: mockSTSServer(correctSignature),
		},
		{
			name: "bad_secret",
			key: awsaccesskey.Credentials{
				AccessID: exampleAccessID,
				Secret:   badSecret,
			},
			want:   veles.ValidationInvalid,
			server: mockSTSServer(correctSignature),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := tc.server()
			client := &http.Client{
				Transport: &mockRoundTripper{url: srv.URL},
			}

			validator := awsaccesskey.NewValidator(
				awsaccesskey.WithHTTPClient(client),
				awsaccesskey.WithSigner(fakeSigner{}),
			)

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
