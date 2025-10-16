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
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gcshmackey"
)

// mockS3Server returns an httptest.Server that simulates an S3 ListBuckets endpoint.
// It accepts only the "testsecret" key; any other secret yields SignatureDoesNotMatch.
func mockS3Server(t *testing.T) *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Print("AAAAA")

		// Only handle ListBuckets (GET /)
		if r.Method != http.MethodGet || r.URL.Path != "/" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		authHeader := r.Header.Get("Authorization")

		// In real S3, the signature is an HMAC of canonical request,
		// but here we just check if the secret string appears in the header.
		switch {
		case strings.Contains(authHeader, "testsecret"):
			// Simulate a valid ListBuckets XML response
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<ListAllMyBucketsResult><Buckets></Buckets></ListAllMyBucketsResult>`)
			return

		case strings.Contains(authHeader, "wrongsecret"):
			// Simulate a SignatureDoesNotMatch error
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `<Error>
				<Code>SignatureDoesNotMatch</Code>
				<Message>The request signature we calculated does not match</Message>
			</Error>`)
			return

		default:
			// Default to invalid signature
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `<Error>
				<Code>AccessDenied</Code>
				<Message>Access Denied</Message>
			</Error>`)
		}
	})

	return httptest.NewServer(handler)
}

func TestValidator(t *testing.T) {
	// Set up fake "GCP metadata" HTTP server.
	srv := mockS3Server(t)
	t.Cleanup(srv.Close)

	validator := gcshmackey.NewValidator(
		gcshmackey.WithURL(srv.URL),
	)

	cases := []struct {
		name string
		key  gcshmackey.HMACKey
		want veles.ValidationStatus
	}{
		{
			name: "ok",
			key: gcshmackey.HMACKey{
				AccessID: "GOOGerkjf4f034",
				Secret:   "testsecret",
			},
			want: veles.ValidationValid,
		},
		{
			name: "bad secret",
			key: gcshmackey.HMACKey{
				AccessID: "GOOGerkjf4f034",
				Secret:   "wrongsecret",
			},
			want: veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
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
