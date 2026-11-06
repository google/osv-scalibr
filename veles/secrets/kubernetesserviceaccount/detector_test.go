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

package kubernetesserviceaccount_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/kubernetesserviceaccount"
	"github.com/google/osv-scalibr/veles/velestest"
)

// testK8sSAJWT is a synthetic JWT with a Kubernetes ServiceAccount payload claim.
// Header: {"alg":"RS256","kid":"abc","typ":"JWT"}
// Payload: {"iss":"kubernetes/serviceaccount","sub":"system:serviceaccount:default:default","kubernetes.io/serviceaccount/namespace":"default","kubernetes.io/serviceaccount/service-account.name":"default","kubernetes.io/serviceaccount/service-account.uid":"12345678-1234-1234-1234-123456789abc","aud":["https://kubernetes.default.svc"],"exp":4468870491}
// Signature: synthetic (not valid cryptographically, but structurally valid)
const testK8sSAJWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiYyIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6ZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvbmFtZXNwYWNlIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5YWJjIiwiYXVkIjpbImh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2YyJdLCJleHAiOjQ0Njg4NzA0OTF9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

// testGenericJWT is a generic JWT without Kubernetes claims.
const testGenericJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		kubernetesserviceaccount.NewDetector(),
		testK8sSAJWT,
		kubernetesserviceaccount.Token{Value: testK8sSAJWT},
	)
}

func TestKubernetesServiceAccountDetector_TruePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{kubernetesserviceaccount.NewDetector()})
	if err != nil {
		t.Fatalf("Failed to initialize detection engine: %v", err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple_matching_token",
		input: testK8sSAJWT,
		want: []veles.Secret{
			kubernetesserviceaccount.Token{Value: testK8sSAJWT},
		},
	}, {
		name:  "token_in_surrounding_text",
		input: "Bearer " + testK8sSAJWT + " end",
		want: []veles.Secret{
			kubernetesserviceaccount.Token{Value: testK8sSAJWT},
		},
	}, {
		name:  "token_in_json_config",
		input: `{"apiVersion":"v1","kind":"Secret","data":{"token":"` + testK8sSAJWT + `"}}`,
		want: []veles.Secret{
			kubernetesserviceaccount.Token{Value: testK8sSAJWT},
		},
	}}

	for _, tc := range cases {
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

func TestKubernetesServiceAccountDetector_TrueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{kubernetesserviceaccount.NewDetector()})
	if err != nil {
		t.Fatalf("Failed to initialize detection engine: %v", err)
	}

	cases := []struct {
		name  string
		input string
	}{{
		name:  "empty_input",
		input: "",
	}, {
		name:  "generic_jwt_without_kubernetes_claims",
		input: testGenericJWT,
	}, {
		name:  "multiple_generic_jwts",
		input: testGenericJWT + "\n" + testGenericJWT,
	}, {
		name:  "random_text",
		input: "this is not a token at all",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			var want []veles.Secret
			if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
