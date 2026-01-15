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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/hcp"
	"github.com/google/osv-scalibr/veles/velestest"
)

func TestAccessTokenDetectorAcceptance(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGguaWRwLmhhc2hpY29ycC5jb20vIiwiYXVkIjpbImh0dHBzOi8vYXBpLmhhc2hpY29ycC5jbG91ZCJdLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	velestest.AcceptDetector(t, hcp.NewAccessTokenDetector(), jwt, hcp.AccessToken{Token: jwt})
}

func TestPairDetector(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{hcp.NewPairDetector()})
	if err != nil {
		t.Fatal(err)
	}

	id := "53au9oDSqR8SBzIy6QJASHnyC1SMQxE2"                                  // 32 chars
	sec := "GGoNkaj1uVBWLO5Lk0-G3duEBK2Mi-w8kUpIJfX7u93fgWqnbMiaKYJgKrO2F6Vc" // 64 chars

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{"param_pair", "hcp_client_id=" + id + "\nhcp_client_secret=" + sec, []veles.Secret{hcp.ClientCredentials{ClientID: id, ClientSecret: sec}}},
		{"env_pair", "HCP_CLIENT_ID=" + id + "\nHCP_CLIENT_SECRET=" + sec, []veles.Secret{hcp.ClientCredentials{ClientID: id, ClientSecret: sec}}},
		{"kv_colon_pair", "hcp_client_id: '" + id + "'\nhcp_client_secret: \"" + sec + "\"", []veles.Secret{hcp.ClientCredentials{ClientID: id, ClientSecret: sec}}},
		{"id_only", "hcp_client_id=" + id, []veles.Secret{hcp.ClientCredentials{ClientID: id}}},
		{"secret_only", "hcp_client_secret=" + sec, []veles.Secret{hcp.ClientCredentials{ClientSecret: sec}}},
		{"wrong_secret", "client_secret=" + id, []veles.Secret{}},
		{"secret_before_id_within_window", "hcp_client_secret=" + sec + "\n...\nHCP_CLIENT_ID=" + id, []veles.Secret{hcp.ClientCredentials{ClientID: id, ClientSecret: sec}}},
		{"too_far_apart", func() string {
			filler := strings.Repeat("a", 10*10*1<<10) // 100 KiB
			return "HCP_CLIENT_ID=" + id + "\n" + filler + "\nHCP_CLIENT_SECRET=" + sec
		}(), []veles.Secret{hcp.ClientCredentials{ClientID: id}, hcp.ClientCredentials{ClientSecret: sec}}},
		{"secret_before_id_too_far", func() string {
			filler := strings.Repeat("b", 10*10*1<<10) // 100 KiB
			return "HCP_CLIENT_SECRET=" + sec + "\n" + filler + "\nHCP_CLIENT_ID=" + id
		}(), []veles.Secret{hcp.ClientCredentials{ClientSecret: sec}, hcp.ClientCredentials{ClientID: id}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("Detect() error: %v", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAccessTokenDetector(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{hcp.NewAccessTokenDetector()})
	if err != nil {
		t.Fatal(err)
	}

	// JWT with strict HCP-like fields in payload: header.payload.signature (base64url)
	payload := "eyJpc3MiOiJodHRwczovL2F1dGguaWRwLmhhc2hpY29ycC5jb20vIiwiYXVkIjpbImh0dHBzOi8vYXBpLmhhc2hpY29ycC5jbG91ZCJdLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMifQ"
	header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	sig := "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	jwt := header + "." + payload + "." + sig

	// Same structure but different issuer (should be rejected)
	payloadWrongIss := "eyJpc3MiOiJodHRwczovL3NvbWUtcmFuZG9tLWlkcC5pbnRlcm5hbC8iLCJhdWQiOlsiaHR0cHM6Ly9hcGkuaGFzaGljb3JwLmNsb3VkIl0sImd0eSI6ImNsaWVudC1jcmVkZW50aWFscyJ9"
	jtwWrong := header + "." + payloadWrongIss + "." + sig

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{"bare_jwt_hcp", jwt, []veles.Secret{hcp.AccessToken{Token: jwt}}},
		{"wrong_issuer", jtwWrong, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("Detect() error: %v", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
