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

package gcshmackey_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gcshmackey"
)

type fakeSigner struct{}

func (n fakeSigner) SignHTTP(_ context.Context, creds aws.Credentials, r *http.Request, _ string, _ string, _ string, _ time.Time, _ ...func(*v4.SignerOptions)) error {
	r.Header.Set("Authorization", "Signature="+creds.AccessKeyID+":"+creds.SecretAccessKey)
	return nil
}

// mockS3Server returns an httptest.Server that simulates an S3 ListBuckets endpoint.
// It accepts only the "testsecret" key; any other secret yields SignatureDoesNotMatch.
func mockS3Server(signature string, denied bool) func() *httptest.Server {
	return func() *httptest.Server {
		handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// Only handle ListBuckets (GET /)
			if req.Method != http.MethodGet || req.URL.Path != "/" {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}

			if !strings.Contains(req.Header.Get("Authorization"), signature) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `<Error>
					<Code>SignatureDoesNotMatch</Code>
					<Message>The request signature we calculated does not match</Message>
				</Error>`)
				return
			}

			if denied {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `<Error>
					<Code>AccessDenied</Code>
				</Error>`)
				return
			}

			w.WriteHeader(http.StatusOK)
		})

		return httptest.NewServer(handler)
	}
}

var (
	exampleAccessID  = "GOOGerkjf4f034"
	correctSecret    = "testsecret"
	badSecret        = "badSecret"
	correctSignature = exampleAccessID + ":" + correctSecret
)

func TestValidator(t *testing.T) {
	// Set up fake "GCP metadata" HTTP server.
	cases := []struct {
		name   string
		key    gcshmackey.HMACKey
		want   veles.ValidationStatus
		server func() *httptest.Server
	}{
		{
			name: "correct secret",
			key: gcshmackey.HMACKey{
				AccessID: exampleAccessID,
				Secret:   correctSecret,
			},
			want:   veles.ValidationValid,
			server: mockS3Server(correctSignature, false),
		},
		{
			name: "correct secret, access denied",
			key: gcshmackey.HMACKey{
				AccessID: exampleAccessID,
				Secret:   correctSecret,
			},
			want:   veles.ValidationValid,
			server: mockS3Server(correctSignature, true),
		},
		{
			name: "bad secret",
			key: gcshmackey.HMACKey{
				AccessID: exampleAccessID,
				Secret:   badSecret,
			},
			want:   veles.ValidationInvalid,
			server: mockS3Server(correctSignature, true),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := tc.server()
			validator := gcshmackey.NewValidator(
				gcshmackey.WithURL(srv.URL),
				gcshmackey.WithSigner(fakeSigner{}),
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
