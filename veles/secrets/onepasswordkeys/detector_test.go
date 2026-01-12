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

// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package onepasswordkeys_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/onepasswordkeys"
)

const (
	testSecretKey       = "A3-XXXXXX-YYYYYY-ZZZZZ-AAAAA-BBBBB-CCCCC"
	testSecretKeyAlt    = "A3-ABC123-DEFGH456789-JKLMN-OPQRS-TUVWX"
	testServiceToken    = "ops_eyJxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	testServiceTokenAlt = "ops_eyJabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
	testRecoveryKey     = "1PRK-ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456-789A-BCDE-FGHI-JKLM-NOPQ"
	testRecoveryKeyAlt  = "1PRK-1234-5678-9ABC-DEFG-HIJK-LMNO-PQRS-TUVW-XYZ1-2345-6789-ABCD-EFGH"
)

// TestSecretKeyDetector_TruePositives tests for cases where we know the SecretKeyDetector
// will find 1Password Secret Key/s.
func TestSecretKeyDetector_TruePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{onepasswordkeys.NewSecretKeyDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: testSecretKey,
		want: []veles.Secret{
			onepasswordkeys.OnePasswordSecretKey{Key: testSecretKey},
		},
	}, {
		name:  "match at end of string",
		input: `OP_SECRET_KEY=` + testSecretKey,
		want: []veles.Secret{
			onepasswordkeys.OnePasswordSecretKey{Key: testSecretKey},
		},
	}, {
		name:  "match in middle of string",
		input: `OP_SECRET_KEY="` + testSecretKey + `"`,
		want: []veles.Secret{
			onepasswordkeys.OnePasswordSecretKey{Key: testSecretKey},
		},
	}, {
		name:  "multiple matches",
		input: testSecretKey + " " + testSecretKey + " " + testSecretKey,
		want: []veles.Secret{
			onepasswordkeys.OnePasswordSecretKey{Key: testSecretKey},
			onepasswordkeys.OnePasswordSecretKey{Key: testSecretKey},
			onepasswordkeys.OnePasswordSecretKey{Key: testSecretKey},
		},
	}, {
		name:  "multiple distinct matches",
		input: testSecretKey + "\n" + testSecretKeyAlt,
		want: []veles.Secret{
			onepasswordkeys.OnePasswordSecretKey{Key: testSecretKey},
			onepasswordkeys.OnePasswordSecretKey{Key: testSecretKeyAlt},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
:test_secret_key: A3-ABCDE-FGHIJ-KLMNO-PQRST-UVWXY-Z1234
:onepassword_secret_key: %s 
		`, testSecretKey),
		want: []veles.Secret{
			onepasswordkeys.OnePasswordSecretKey{Key: testSecretKey},
		},
	}, {
		name:  "potential match with extra characters",
		input: testSecretKey + `extra`,
		want: []veles.Secret{
			onepasswordkeys.OnePasswordSecretKey{Key: testSecretKey},
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

// TestSecretKeyDetector_TrueNegatives tests for cases where we know the SecretKeyDetector
// will not find a 1Password Secret Key.
func TestSecretKeyDetector_TrueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{onepasswordkeys.NewSecretKeyDetector()})
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
		name:  "wrong prefix",
		input: `A2-XXXXXX-YYYYYY-ZZZZZ-AAAAA-BBBBB-CCCCC`,
	}, {
		name:  "missing prefix dash",
		input: `A3XXXXXX-YYYYYY-ZZZZZ-AAAAA-BBBBB-CCCCC`,
	}, {
		name:  "invalid character in first segment",
		input: `A3-XXXX!X-YYYYYY-ZZZZZ-AAAAA-BBBBB-CCCCC`,
	}, {
		name:  "first segment too short",
		input: `A3-XXXXX-YYYYYY-ZZZZZ-AAAAA-BBBBB-CCCCC`,
	}, {
		name:  "first segment too long",
		input: `A3-XXXXXXX-YYYYYY-ZZZZZ-AAAAA-BBBBB-CCCCC`,
	}, {
		name:  "invalid middle segment length",
		input: `A3-XXXXXX-YYYYY-ZZZZZ-AAAAA-BBBBB-CCCCC`,
	}, {
		name:  "last segment too short",
		input: `A3-XXXXXX-YYYYYY-ZZZZZ-AAAAA-BBBBB-CCCC`,
	}, {
		name:  "lowercase characters",
		input: `a3-xxxxxx-yyyyyy-zzzzz-aaaaa-bbbbb-ccccc`,
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

// TestServiceTokenDetector_TruePositives tests for cases where we know the ServiceTokenDetector
// will find 1Password Service Token/s.
func TestServiceTokenDetector_TruePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{onepasswordkeys.NewServiceTokenDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: testServiceToken,
		want: []veles.Secret{
			onepasswordkeys.OnePasswordServiceToken{Key: testServiceToken},
		},
	}, {
		name:  "match at end of string",
		input: `OP_SERVICE_ACCOUNT_TOKEN=` + testServiceToken,
		want: []veles.Secret{
			onepasswordkeys.OnePasswordServiceToken{Key: testServiceToken},
		},
	}, {
		name:  "match in middle of string",
		input: `OP_SERVICE_ACCOUNT_TOKEN="` + testServiceToken + `"`,
		want: []veles.Secret{
			onepasswordkeys.OnePasswordServiceToken{Key: testServiceToken},
		},
	}, {
		name:  "multiple matches",
		input: testServiceToken + " " + testServiceToken + " " + testServiceToken,
		want: []veles.Secret{
			onepasswordkeys.OnePasswordServiceToken{Key: testServiceToken},
			onepasswordkeys.OnePasswordServiceToken{Key: testServiceToken},
			onepasswordkeys.OnePasswordServiceToken{Key: testServiceToken},
		},
	}, {
		name:  "multiple distinct matches",
		input: testServiceToken + "\n" + testServiceTokenAlt,
		want: []veles.Secret{
			onepasswordkeys.OnePasswordServiceToken{Key: testServiceToken},
			onepasswordkeys.OnePasswordServiceToken{Key: testServiceTokenAlt},
		},
	}, {
		name: "larger_input_containing_token",
		input: fmt.Sprintf(`
:test_service_token: ops_eyJtest
:onepassword_service_token: %s 
		`, testServiceToken),
		want: []veles.Secret{
			onepasswordkeys.OnePasswordServiceToken{Key: testServiceToken},
		},
	}, {
		name:  "token with padding",
		input: testServiceToken + "===",
		want: []veles.Secret{
			onepasswordkeys.OnePasswordServiceToken{Key: testServiceToken + "==="},
		},
	}, {
		name:  "potential match with extra whitespace",
		input: testServiceToken + ` `,
		want: []veles.Secret{
			onepasswordkeys.OnePasswordServiceToken{Key: testServiceToken},
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

// TestServiceTokenDetector_TrueNegatives tests for cases where we know the ServiceTokenDetector
// will not find a 1Password Service Token.
func TestServiceTokenDetector_TrueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{onepasswordkeys.NewServiceTokenDetector()})
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
		name:  "wrong prefix",
		input: `op_eyJxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}, {
		name:  "missing underscore in prefix",
		input: `opseyJxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}, {
		name:  "token too short",
		input: `ops_eyJabcdefghijklmnopqrstuvwxyz`,
	}, {
		name:  "invalid character in token",
		input: `ops_eyJ` + strings.Repeat("a", 100) + `!` + strings.Repeat("a", 149),
	}, {
		name:  "too much padding",
		input: `ops_eyJ` + strings.Repeat("a", 50) + `====`,
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

// TestRecoveryKeyDetector_TruePositives tests for cases where we know the RecoveryKeyDetector
// will find 1Password Recovery Key/s.
func TestRecoveryKeyDetector_TruePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{onepasswordkeys.NewRecoveryTokenDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: testRecoveryKey,
		want: []veles.Secret{
			onepasswordkeys.OnePasswordRecoveryCode{Key: testRecoveryKey},
		},
	}, {
		name:  "match at end of string",
		input: `OP_RECOVERY_KEY=` + testRecoveryKey,
		want: []veles.Secret{
			onepasswordkeys.OnePasswordRecoveryCode{Key: testRecoveryKey},
		},
	}, {
		name:  "match in middle of string",
		input: `OP_RECOVERY_KEY="` + testRecoveryKey + `"`,
		want: []veles.Secret{
			onepasswordkeys.OnePasswordRecoveryCode{Key: testRecoveryKey},
		},
	}, {
		name:  "multiple matches",
		input: testRecoveryKey + " " + testRecoveryKey + " " + testRecoveryKey,
		want: []veles.Secret{
			onepasswordkeys.OnePasswordRecoveryCode{Key: testRecoveryKey},
			onepasswordkeys.OnePasswordRecoveryCode{Key: testRecoveryKey},
			onepasswordkeys.OnePasswordRecoveryCode{Key: testRecoveryKey},
		},
	}, {
		name:  "multiple distinct matches",
		input: testRecoveryKey + "\n" + testRecoveryKeyAlt,
		want: []veles.Secret{
			onepasswordkeys.OnePasswordRecoveryCode{Key: testRecoveryKey},
			onepasswordkeys.OnePasswordRecoveryCode{Key: testRecoveryKeyAlt},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
:test_recovery_key: 1PRK-ABCD-EFGH-IJKL
:onepassword_recovery_key: %s 
		`, testRecoveryKey),
		want: []veles.Secret{
			onepasswordkeys.OnePasswordRecoveryCode{Key: testRecoveryKey},
		},
	}, {
		name:  "potential match with extra characters",
		input: testRecoveryKey + `extra`,
		want: []veles.Secret{
			onepasswordkeys.OnePasswordRecoveryCode{Key: testRecoveryKey},
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

// TestRecoveryKeyDetector_TrueNegatives tests for cases where we know the RecoveryKeyDetector
// will not find a 1Password Recovery Key.
func TestRecoveryKeyDetector_TrueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{onepasswordkeys.NewRecoveryTokenDetector()})
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
		name:  "wrong prefix",
		input: `1PRX-ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456-789A-BCDE-FGHI-JKLM-NOPQ`,
	}, {
		name:  "missing prefix dash",
		input: `1PRKABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456-789A-BCDE-FGHI-JKLM-NOPQ`,
	}, {
		name:  "too few segments",
		input: `1PRK-ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456-789A-BCDE-FGHI-JKLM`,
	}, {
		name:  "segment too short",
		input: `1PRK-ABC-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456-789A-BCDE-FGHI-JKLM-NOPQ`,
	}, {
		name:  "segment too long",
		input: `1PRK-ABCDE-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456-789A-BCDE-FGHI-JKLM-NOPQ`,
	}, {
		name:  "invalid character in segment",
		input: `1PRK-AB!D-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456-789A-BCDE-FGHI-JKLM-NOPQ`,
	}, {
		name:  "lowercase characters",
		input: `1prk-abcd-efgh-ijkl-mnop-qrst-uvwx-yz12-3456-789a-bcde-fghi-jklm-nopq`,
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
