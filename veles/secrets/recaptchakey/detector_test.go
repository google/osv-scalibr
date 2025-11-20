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

package recaptchakey_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/recaptchakey"
)

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{recaptchakey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "empty_input",
			input: "",
			want:  nil,
		},
		{
			name:  "random_input",
			input: "Some random text",
			want:  nil,
		},
		{
			name: "python",
			input: `
			RECAPTCHA_PUBLIC_KEY = '6LcA1x0UAAAAAF1b2Qp9Zp3t0TestKeyPublic01'
			RECAPTCHA_PRIVATE_KEY = '6LeA1x0UAAAAAG1b2Qp9Zp3t0TestKeyPrivate1'`,
			want: []veles.Secret{
				recaptchakey.Key{
					Secret: "6LeA1x0UAAAAAG1b2Qp9Zp3t0TestKeyPrivate1",
				},
			},
		},
		{
			name: "yaml_simple",
			input: `
   		recaptcha_site_key: 6LcD4a3XAA-AAE7n9Gu2St3y3TestKeyPublic02
    	recaptcha_secret_key: 6LeD4a3XAAAAA-7n9Gu2St3y3TestKeyPrivate2
			`,
			want: []veles.Secret{
				recaptchakey.Key{
					Secret: "6LeD4a3XAAAAA-7n9Gu2St3y3TestKeyPrivate2",
				},
			},
		},
		{
			name: "yaml_multiline",
			input: `
		  recaptcha:
		    public_key: 6LcA1x0UAAAAAF-1b2Qp9Zp3t-TestKeyPublic3
		    private_key: 6LeH8e7VAAAAAG1r3Ky6Wx7c7TestKeyPrivate3
			`,
			want: []veles.Secret{
				recaptchakey.Key{
					Secret: "6LeH8e7VAAAAAG1r3Ky6Wx7c7TestKeyPrivate3",
				},
			},
		},
		{
			name: "yaml_multiline_another_key",
			input: `
		  recaptcha:
		    public_key: 6LcA1x0UAAAAAF-1b2Qp9Zp3t-TestKeyPublic3
		    private_key: ***
			another_key:
				private_key: 6LeH8e7VAAAAAG1r3Ky6Wx7c7TestKeyPrivate3
			`,
			want: nil,
		},
		{
			name: "yaml_indented",
			input: `
			someIndentation:
			  recaptcha:
			    public_key: 6LcA1x0UAAAAAF-1b2Qp9Zp3t-TestKeyPublic3
					private_key: 6LeH8e7VAAAAAG1r3Ky6Wx7c7TestKeyPrivate3
			`,
			want: nil,
		},
		{
			name: "yaml_indented_with_tabs",
			input: `
` + "\t" + `recaptcha:
` + "\t\t" + `public_key: 6LcA1x0UAAAAAF-1b2Qp9Zp3t-TestKeyPublic3
` + "\t\t" + `private_key: 6LeH8e7VAAAAAG1r3Ky6Wx7c7TestKeyPrivate3`,
			want: nil,
		},
		{
			name: "no_space_env",
			input: `
	    RECAPTCHA_PRIVATE_KEY=6LeA1x0UAAAAAG1b2Qp9Zp3t0TestKeyPrivate1
	    `,
			want: []veles.Secret{
				recaptchakey.Key{Secret: "6LeA1x0UAAAAAG1b2Qp9Zp3t0TestKeyPrivate1"},
			},
		},
		{
			name: "simple_yaml",
			input: `
# This is a comment
recaptcha_secret_key: 6LeF9x0UAAAAAG1b2Qp9Zp3t0PrivateComment1
# Another comment
recaptcha_site_key: 6LcF9x0UAAAAAF1b2Qp9Zp3t01PublicComment1
`,
			want: []veles.Secret{
				recaptchakey.Key{Secret: "6LeF9x0UAAAAAG1b2Qp9Zp3t0PrivateComment1"},
			},
		},
		{
			name: "yaml_with_nested_comments",
			input: `
reCaptcha:
  # Inline comment for public key
  public_key: 6LcH1x0UAAAAAF-1b2Qp9Z11p3t-PublicNested
  private_key: 6LeH1x0UAAAAAG1r3Ky6Wx7c711PrivateNested
# Comment outside mapping
`,
			want: []veles.Secret{
				recaptchakey.Key{Secret: "6LeH1x0UAAAAAG1r3Ky6Wx7c711PrivateNested"},
			},
		},
		{
			name: "multiple_keys_env",
			input: `
	    RECAPTCHA_PRIVATE_KEY = '6LeA1x0UAAAAAG1b2Qp9Zp3t0TestKeyPrivate1'
	    recaptcha_secret_key: 6LeD4a3XAAAAA-7n9Gu2St3y3TestKeyPrivate2
	    `,
			want: []veles.Secret{
				recaptchakey.Key{Secret: "6LeA1x0UAAAAAG1b2Qp9Zp3t0TestKeyPrivate1"},
				recaptchakey.Key{Secret: "6LeD4a3XAAAAA-7n9Gu2St3y3TestKeyPrivate2"},
			},
		},
		{
			name: "invalid_key",
			input: `
	    NOT_A_KEY = "6LeD4a3XAAAAA-INVALID-1234567890"
	    `,
			want: nil,
		},
		{
			name: "key_value_json",
			input: `
	    {
	      "recaptcha_public_key": "6LcA1x0UAAAAAF-1b2Qp9Zp3y3TestKeyPublic3",
	      "recaptcha_secret_key": "6LeH8e7VAAAAAG1r3Ky6Wx7c7TestKeyPrivate3"
	    }
	    `,
			want: []veles.Secret{
				recaptchakey.Key{Secret: "6LeH8e7VAAAAAG1r3Ky6Wx7c7TestKeyPrivate3"},
			},
		},
		{
			name: "multiline_json",
			input: `{
			  "recaptcha": {
					"public_key": "6LcA1x0UAAAAAF-1b2Qp9Zp3y3TestKeyPublic3",
				  "secret_key": "6LeH8e7VAAAAAG1r3Ky6Wx7c7TestKeyPrivate3"
				}
			}`,
			want: []veles.Secret{
				recaptchakey.Key{Secret: "6LeH8e7VAAAAAG1r3Ky6Wx7c7TestKeyPrivate3"},
			},
		},
		{
			name:  "inline_json",
			input: `{"recaptcha": {"public_key": "6LcA1x0UAAAAAF-1b2Qp9Zp3y3TestKeyPublic3","secret_key": "6LeH8e7VAAAAAG1r3Ky6Wx7c7TestKeyPrivate3"}}`,
			want: []veles.Secret{
				recaptchakey.Key{Secret: "6LeH8e7VAAAAAG1r3Ky6Wx7c7TestKeyPrivate3"},
			},
		},
		{
			name:  "escaped_json",
			input: `{\n  \"recaptcha\": {\n		\"public_key\": \"6LcA1x0UAAAAAF-1b2Qp9Zp3y3TestKeyPublic3\",\n	  \"secret_key\": \"6LeH8e7VAAAAAG1r3Ky6Wx7c7TestKeyPrivate3\"\n	}\n}`,
			want: []veles.Secret{
				recaptchakey.Key{Secret: "6LeH8e7VAAAAAG1r3Ky6Wx7c7TestKeyPrivate3"},
			},
		},
		{
			name: "escaped_key_value_json",
			input: `
	    {
	      "recaptcha_public_key": "6LcA1x0UAAAAAF-1b2Qp9Zp3y3TestKeyPublic3",
	      "recaptcha_secret_key": "6LeH8e7VAAAAAG1r3Ky6Wx7c7TestKeyPrivate3"
	    }
	    `,
			want: []veles.Secret{
				recaptchakey.Key{Secret: "6LeH8e7VAAAAAG1r3Ky6Wx7c7TestKeyPrivate3"},
			},
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
