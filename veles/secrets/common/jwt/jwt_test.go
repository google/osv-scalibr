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

// TestExtractTokens_validTokens tests for cases where we expect to
// successfully extract tokens.
func TestExtractTokens_validTokens(t *testing.T) {
	cases := []struct {
		name          string
		input         []byte
		wantRaw       []string
		wantHeader    []map[string]any
		wantPayload   []map[string]any
		wantSignature []string
		wantPos       []int
	}{
		{
			name: "basic_jwt_with_simple_claims",
			input: []byte("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature"),
			wantRaw: []string{
				"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
					"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature",
			},
			wantHeader: []map[string]any{
				{
					"alg": "RS256",
					"typ": "JWT",
				},
			},
			wantPayload: []map[string]any{
				{
					"sub":  "1234567890",
					"name": "John Doe",
					"iat":  float64(1516239022),
				},
			},

			wantPos: []int{0},
		},
		{
			name: "azure_token",
			input: []byte("prefix eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vdGVuYW50L3YyLjAiLCJzdWIiOiJ1c2VyMTIzIn0.signature suffix"),
			wantRaw: []string{
				"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
					"eyJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vdGVuYW50L3YyLjAiLCJzdWIiOiJ1c2VyMTIzIn0.signature",
			},
			wantHeader: []map[string]any{
				{
					"alg": "RS256",
					"typ": "JWT",
				},
			},
			wantPayload: []map[string]any{
				{
					"iss": "https://login.microsoftonline.com/tenant/v2.0",
					"sub": "user123",
				},
			},
			wantSignature: []string{"signature"},
			wantPos:       []int{7},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotTokens, gotPos := jwt.ExtractTokens(tc.input)

			if diff := cmp.Diff(tc.wantPos, gotPos); diff != "" {
				t.Errorf("ExtractTokens(): diff position mismatch (-want +got):\n%s", diff)
			}

			if len(gotTokens) != len(tc.wantRaw) {
				t.Fatalf("ExtractTokens(): diff number of tokens: got %d, want %d", len(gotTokens), len(tc.wantRaw))
			}

			for i, got := range gotTokens {
				if got.Raw() != tc.wantRaw[i] {
					t.Errorf("ExtractTokens(): diff %d Raw() = %q; want %q", i, got.Raw(), tc.wantRaw[i])
				}

				if diff := cmp.Diff(tc.wantHeader[i], got.Header(), cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("ExtractTokens(): diff %d Header() mismatch (-want +got):\n%s", i, diff)
				}

				if diff := cmp.Diff(tc.wantPayload[i], got.Payload(), cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("ExtractTokens(): diff %d Payload() mismatch (-want +got):\n%s", i, diff)
				}
			}
		})
	}
}

// TestExtractTokens_invalidTokens tests for cases where we expect to return nil.
func TestExtractTokens_invalidTokens(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
	}{
		{
			name:  "empty string",
			input: []byte(""),
		},
		{
			name:  "only one part",
			input: []byte("header"),
		},
		{
			name:  "only two parts",
			input: []byte("header.payload"),
		},
		{
			name:  "too many parts",
			input: []byte("header.payload.signature.extra"),
		},
		{
			name:  "invalid base64 in payload",
			input: []byte("eyJhbGciOiJSUzI1NiJ9.invalid_base64!.signature"),
		},
		{
			name: "payload_is_not_json",
			input: []byte("eyJhbGciOiJSUzI1NiJ9." +
				base64.RawStdEncoding.EncodeToString([]byte("not json")) +
				".signature"),
		},
		{
			name:  "not valid regex",
			input: []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.signature"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotTokens, gotPos := jwt.ExtractTokens(tc.input)

			if len(gotTokens) != 0 {
				t.Errorf("ExtractTokens(): diff returned %d tokens; want 0", len(gotTokens))
			}

			if len(gotPos) != 0 {
				t.Errorf("ExtractTokens(): diff returned %d positions; want 0", len(gotPos))
			}
		})
	}
}
