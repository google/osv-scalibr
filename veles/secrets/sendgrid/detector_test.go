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

package sendgrid_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/sendgrid"
	"github.com/google/osv-scalibr/veles/velestest"
)

// Fake SendGrid API keys for testing purposes.
// These are NOT real keys and will not work with the SendGrid API.
// They follow the correct format: SG.<22 chars>.<43 chars> = 69 total characters.
const testSendGridAPIKey = "SG.aaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const testSendGridAPIKey2 = "SG.XXXXXXXXXXXXXXXXXXXXXX.YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"
const testSendGridAPIKeyWithSpecialChars = "SG.abc_def-ghij12345678ab.ABC_DEF-GHIJKLMNOPQRSTUVWXYZabcdefghijk1234"

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		sendgrid.NewDetector(),
		testSendGridAPIKey,
		sendgrid.APIKey{Key: testSendGridAPIKey},
	)
}

// TestDetector_truePositives tests for cases where we know the Detector
// will find SendGrid API keys.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{
		sendgrid.NewDetector(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: testSendGridAPIKey,
		want: []veles.Secret{
			sendgrid.APIKey{Key: testSendGridAPIKey},
		},
	}, {
		name:  "key with underscores and dashes",
		input: testSendGridAPIKeyWithSpecialChars,
		want: []veles.Secret{
			sendgrid.APIKey{Key: testSendGridAPIKeyWithSpecialChars},
		},
	}, {
		name:  "match at end of string",
		input: "SENDGRID_API_KEY=" + testSendGridAPIKey,
		want: []veles.Secret{
			sendgrid.APIKey{Key: testSendGridAPIKey},
		},
	}, {
		name:  "match in middle of string",
		input: `api_key="` + testSendGridAPIKey + `"`,
		want: []veles.Secret{
			sendgrid.APIKey{Key: testSendGridAPIKey},
		},
	}, {
		name:  "multiple matches",
		input: testSendGridAPIKey + "\n" + testSendGridAPIKey2,
		want: []veles.Secret{
			sendgrid.APIKey{Key: testSendGridAPIKey},
			sendgrid.APIKey{Key: testSendGridAPIKey2},
		},
	}, {
		name:  "key in JSON format",
		input: `{"sendgrid_api_key": "` + testSendGridAPIKey + `"}`,
		want: []veles.Secret{
			sendgrid.APIKey{Key: testSendGridAPIKey},
		},
	}, {
		name:  "key in environment variable style",
		input: `export SENDGRID_API_KEY="` + testSendGridAPIKey + `"`,
		want: []veles.Secret{
			sendgrid.APIKey{Key: testSendGridAPIKey},
		},
	}, {
		name: "larger input containing key",
		input: fmt.Sprintf(`
:test_api_key: do-test
:SENDGRID_API_KEY: %s
		`, testSendGridAPIKey),
		want: []veles.Secret{
			sendgrid.APIKey{Key: testSendGridAPIKey},
		},
	}, {
		name:  "key followed by extra characters",
		input: testSendGridAPIKey + "extra",
		want: []veles.Secret{
			sendgrid.APIKey{Key: testSendGridAPIKey},
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
// will not find SendGrid API keys.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{
		sendgrid.NewDetector(),
	})
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
		name:  "wrong prefix - not SG.",
		input: "XX.abcdefghij1234567890AB.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk1234",
	}, {
		name:  "lowercase sg prefix should not match",
		input: "sg.abcdefghij1234567890AB.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk1234",
	}, {
		name:  "too short key_id section",
		input: "SG.short.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk1234",
	}, {
		name:  "too short key_secret section",
		input: "SG.abcdefghij1234567890AB.short",
	}, {
		name:  "invalid characters in key_id - special chars",
		input: "SG.abcdefghij123456!@#$.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk1234",
	}, {
		name:  "invalid characters in key_secret - special chars",
		input: "SG.abcdefghij1234567890AB.ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$efghijk1234",
	}, {
		name:  "missing first dot",
		input: "SGabcdefghij1234567890AB.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk1234",
	}, {
		name:  "missing second dot",
		input: "SG.abcdefghij1234567890ABABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk1234",
	}, {
		name:  "random text without any keys",
		input: "this is some random text without any API keys",
	}, {
		name:  "partial key - truncated",
		input: testSendGridAPIKey[:len(testSendGridAPIKey)-1],
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

func TestSendGridKeyFormat(t *testing.T) {
	// Test that our fake keys are the correct length
	tests := []struct {
		name string
		key  string
	}{
		{"testSendGridAPIKey", testSendGridAPIKey},
		{"testSendGridAPIKey2", testSendGridAPIKey2},
		{"testSendGridAPIKeyWithSpecialChars", testSendGridAPIKeyWithSpecialChars},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.key) != 69 {
				t.Errorf("%s has length %d, want 69", tt.name, len(tt.key))
			}
			if tt.key[:3] != "SG." {
				t.Errorf("%s doesn't start with 'SG.'", tt.name)
			}
		})
	}
}
