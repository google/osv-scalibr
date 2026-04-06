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

package mongodbatlasapikey_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/mongodbatlasapikey"
)

const (
	testPublicKey  = "abcdef01"
	testPrivateKey = "12345678-abcd-1234-abcd-123456789012"
)

// TestDetector_truePositives tests for cases where we know the Detector
// will find MongoDB Atlas API keys.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{mongodbatlasapikey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name: "toml config pair",
		input: `[default]
  public_api_key = "abcdef01"
  private_api_key = "12345678-abcd-1234-abcd-123456789012"`,
		want: []veles.Secret{
			mongodbatlasapikey.APIKey{PublicKey: testPublicKey, PrivateKey: testPrivateKey},
		},
	}, {
		name: "env var style pair",
		input: `MONGODB_ATLAS_PUBLIC_KEY=abcdef01
MONGODB_ATLAS_PRIVATE_KEY=12345678-abcd-1234-abcd-123456789012`,
		want: []veles.Secret{
			mongodbatlasapikey.APIKey{PublicKey: testPublicKey, PrivateKey: testPrivateKey},
		},
	}, {
		name: "yaml style pair",
		input: `public_api_key: abcdef01
private_api_key: 12345678-abcd-1234-abcd-123456789012`,
		want: []veles.Secret{
			mongodbatlasapikey.APIKey{PublicKey: testPublicKey, PrivateKey: testPrivateKey},
		},
	}, {
		name:  "private key only",
		input: `private_api_key = "12345678-abcd-1234-abcd-123456789012"`,
		want: []veles.Secret{
			mongodbatlasapikey.APIKey{PrivateKey: testPrivateKey},
		},
	}, {
		name:  "public key only",
		input: `public_api_key = "abcdef01"`,
		want: []veles.Secret{
			mongodbatlasapikey.APIKey{PublicKey: testPublicKey},
		},
	}, {
		name: "config with surrounding context",
		input: `# MongoDB Atlas configuration
[default]
  org_id = "5f0a1d2b3c4e5f6a7b8c9d0e"
  public_api_key = "abcdef01"
  private_api_key = "12345678-abcd-1234-abcd-123456789012"
  service = "cloud"`,
		want: []veles.Secret{
			mongodbatlasapikey.APIKey{PublicKey: testPublicKey, PrivateKey: testPrivateKey},
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

// TestDetector_trueNegatives tests for cases where we know the Detector
// will not find MongoDB Atlas API keys.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{mongodbatlasapikey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "empty input",
		input: "",
	}, {
		name:  "random uuid without context",
		input: "12345678-abcd-1234-abcd-123456789012",
	}, {
		name:  "short public key without context",
		input: "abcdef01",
	}, {
		name:  "unrelated config key",
		input: `api_key = "abcdef01"`,
	}, {
		name:  "invalid uuid format",
		input: `private_api_key = "not-a-valid-uuid-format"`,
	}, {
		name:  "public key too long",
		input: `public_api_key = "abcdefghij"`,
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
