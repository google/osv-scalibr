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

package supabase_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/supabase"
	"github.com/google/osv-scalibr/veles/velestest"
)

func TestSupabasePATDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		supabase.NewPATDetector(),
		"sbp_1234567890abcdef1234567890abcdef12345678",
		supabase.PAT{Token: "sbp_1234567890abcdef1234567890abcdef12345678"},
		velestest.WithBackToBack(),
	)
}

func TestSupabasePATDetector(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{supabase.NewPATDetector()})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "valid_pat",
			input: "token: sbp_1234567890abcdef1234567890abcdef12345678",
			want: []veles.Secret{
				supabase.PAT{Token: "sbp_1234567890abcdef1234567890abcdef12345678"},
			},
		},
		{
			name:  "multiple_pats",
			input: "token1: sbp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\ntoken2: sbp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			want: []veles.Secret{
				supabase.PAT{Token: "sbp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
				supabase.PAT{Token: "sbp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
			},
		},
		{
			name:  "invalid_pat_too_short",
			input: "token: sbp_123",
			want:  nil,
		},
		{
			name:  "invalid_pat_wrong_chars",
			input: "token: sbp_GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
			want:  nil,
		},
		{
			name:  "no_pat",
			input: "some random text without tokens",
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSupabaseProjectSecretKeyDetector(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{supabase.NewProjectSecretKeyDetector()})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name: "valid_project_secret_with_ref_31_chars",
			input: `
https://lphyfymaepklpuvaecry.supabase.co
sb_secret_Ot4elAPTTzLF2SFwFTS6-A_bL775S0X
`,
			want: []veles.Secret{
				supabase.ProjectSecretKey{
					Key:        "sb_secret_Ot4elAPTTzLF2SFwFTS6-A_bL775S0X",
					ProjectRef: "lphyfymaepklpuvaecry",
				},
			},
		},
		{
			name: "valid_project_secret_with_ref_32_chars",
			input: `
https://xyzabc1234567890abcd.supabase.co
sb_secret_9EgwCcN2mv9mxBcrBSBKAw_C2vJk2Ohs
`,
			want: []veles.Secret{
				supabase.ProjectSecretKey{
					Key:        "sb_secret_9EgwCcN2mv9mxBcrBSBKAw_C2vJk2Ohs",
					ProjectRef: "xyzabc1234567890abcd",
				},
			},
		},
		{
			name: "valid_project_secret_with_ref_36_chars",
			input: `
https://abcdefgh1234567890ij.supabase.co
sb_secret_IhKHyoXGkvuHXVlFMSQpWw_NOEnkUl6ABC
`,
			want: []veles.Secret{
				supabase.ProjectSecretKey{
					Key:        "sb_secret_IhKHyoXGkvuHXVlFMSQpWw_NOEnkUl6ABC",
					ProjectRef: "abcdefgh1234567890ij",
				},
			},
		},
		{
			name: "valid_project_secret_with_ref_reversed_order",
			input: `
sb_secret_abcdefghijklmnopqrstuvwxyz123456
https://xyz1234567890abcdefg.supabase.co
`,
			want: []veles.Secret{
				supabase.ProjectSecretKey{
					Key:        "sb_secret_abcdefghijklmnopqrstuvwxyz123456",
					ProjectRef: "xyz1234567890abcdefg",
				},
			},
		},
		{
			name: "valid_with_rest_endpoint",
			input: `
sb_secret_Ot4elAPTTzLF2SFwFTS6-A_bL775S0X
https://lphyfymaepklpuvaecry.supabase.co/rest/v1/
`,
			want: []veles.Secret{
				supabase.ProjectSecretKey{
					Key:        "sb_secret_Ot4elAPTTzLF2SFwFTS6-A_bL775S0X",
					ProjectRef: "lphyfymaepklpuvaecry",
				},
			},
		},
		{
			name:  "secret_key_without_project_ref",
			input: "sb_secret_abcdefghijklmnopqrstuvwxyz123456",
			want:  nil,
		},
		{
			name:  "project_ref_without_secret_key",
			input: "https://lphyfymaepklpuvaecry.supabase.co",
			want:  nil,
		},
		{
			name:  "invalid_secret_key_too_short",
			input: "sb_secret_short",
			want:  nil,
		},
		{
			name:  "invalid_secret_key_30_chars",
			input: "sb_secret_abcdefghijklmnopqrstuvwxy",
			want:  nil,
		},
		{
			name:  "invalid_secret_key_37_chars_too_long",
			input: "sb_secret_abcdefghijklmnopqrstuvwxyz12345678901",
			want:  nil,
		},
		{
			name:  "no_secrets",
			input: "some random text without secrets",
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSupabaseServiceRoleJWTDetector(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{supabase.NewServiceRoleJWTDetector()})
	if err != nil {
		t.Fatal(err)
	}

	// Valid service_role JWT with iss="supabase" and role="service_role"
	// Header: {"alg":"HS256","typ":"JWT"}
	// Payload: {"iss":"supabase","role":"service_role","iat":1234567890}
	validServiceRoleJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUiLCJpYXQiOjEyMzQ1Njc4OTB9.signature"

	// Invalid: anon role
	// Payload: {"iss":"supabase","role":"anon","iat":1234567890}
	invalidAnonJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJhbm9uIiwiaWF0IjoxMjM0NTY3ODkwfQ.signature"

	// Invalid: wrong issuer
	// Payload: {"iss":"other","role":"service_role","iat":1234567890}
	invalidIssuerJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJvdGhlciIsInJvbGUiOiJzZXJ2aWNlX3JvbGUiLCJpYXQiOjEyMzQ1Njc4OTB9.signature"

	// Invalid: generic JWT
	// Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022}
	genericJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "valid_service_role_jwt",
			input: validServiceRoleJWT,
			want: []veles.Secret{
				supabase.ServiceRoleJWT{Token: validServiceRoleJWT},
			},
		},
		{
			name:  "valid_service_role_jwt_in_config",
			input: "SUPABASE_SERVICE_ROLE_KEY=" + validServiceRoleJWT,
			want: []veles.Secret{
				supabase.ServiceRoleJWT{Token: validServiceRoleJWT},
			},
		},
		{
			name:  "invalid_anon_jwt",
			input: invalidAnonJWT,
			want:  nil,
		},
		{
			name:  "invalid_issuer_jwt",
			input: invalidIssuerJWT,
			want:  nil,
		},
		{
			name:  "invalid_generic_jwt",
			input: genericJWT,
			want:  nil,
		},
		{
			name:  "no_jwt",
			input: "some random text without jwt",
			want:  nil,
		},
		{
			name:  "malformed_jwt",
			input: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
