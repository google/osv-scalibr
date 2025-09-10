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

package jwt_test

import (
	"encoding/base64"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles/secrets/common/jwt"
)

// TestExtractClaimsPayload_validTokens tests for cases where we expect
// ExtractClaimsPayload to successfully extract claims.
func TestExtractClaimsPayload_validTokens(t *testing.T) {
	cases := []struct {
		name  string
		token string
		want  map[string]any
	}{{
		name:  "basic jwt with simple claims",
		token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature",
		want: map[string]any{
			"sub":  "1234567890",
			"name": "John Doe",
			"iat":  float64(1516239022),
		},
	}, {
		name:  "azure token",
		token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vdGVuYW50L3YyLjAiLCJzdWIiOiJ1c2VyMTIzIn0.signature",
		want: map[string]any{
			"iss": "https://login.microsoftonline.com/tenant/v2.0",
			"sub": "user123",
		},
	}, {
		name:  "empty claims",
		token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature",
		want:  map[string]any{},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := jwt.ExtractClaimsPayload(tc.token)
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("ExtractClaimsPayload() diff (-want +got):\n%s", diff)
			}
		})
	}
}

// TestExtractClaimsPayload_invalidTokens tests for cases where we expect
// ExtractClaimsPayload to return nil.
func TestExtractClaimsPayload_invalidTokens(t *testing.T) {
	cases := []struct {
		name  string
		token string
	}{{
		name:  "empty string",
		token: "",
	}, {
		name:  "only one part",
		token: "header",
	}, {
		name:  "only two parts",
		token: "header.payload",
	}, {
		name:  "too many parts",
		token: "header.payload.signature.extra",
	}, {
		name:  "invalid base64 in payload",
		token: "eyJhbGciOiJSUzI1NiJ9.invalid_base64!.signature",
	}, {
		name:  "payload is not json",
		token: "eyJhbGciOiJSUzI1NiJ9." + base64.RawStdEncoding.EncodeToString([]byte("not json")) + ".signature",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := jwt.ExtractClaimsPayload(tc.token)
			if got != nil {
				t.Errorf("ExtractClaimsPayload(%q) = %v, want nil", tc.token, got)
			}
		})
	}
}
