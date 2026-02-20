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

package dropboxappaccesstoken_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/dropboxappaccesstoken"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	// A realistic-looking Dropbox short-lived access token for testing.
	validToken = "sl.u.AGRu-v0jufTn6fQRX1rY400Kx6oey8q6W6eh2ZOTtAn2P8756KRz77uDov18PWbWoMf1tggrceuFSJ7H6NKtUiZPLu3Rp9d"
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		dropboxappaccesstoken.NewDetector(),
		validToken,
		dropboxappaccesstoken.APIAccessToken{Token: validToken},
	)
}

func TestDetector(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{dropboxappaccesstoken.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "dropbox_token",
		input: validToken,
		want: []veles.Secret{
			dropboxappaccesstoken.APIAccessToken{Token: validToken},
		},
	}, {
		name:  "dropbox_token_in_config",
		input: "DROPBOX_ACCESS_TOKEN=" + validToken,
		want: []veles.Secret{
			dropboxappaccesstoken.APIAccessToken{Token: validToken},
		},
	}, {
		name:  "dropbox_token_in_env",
		input: "export DROPBOX_TOKEN=\"" + validToken + "\"",
		want: []veles.Secret{
			dropboxappaccesstoken.APIAccessToken{Token: validToken},
		},
	}, {
		name: "multiple_dropbox_tokens",
		input: validToken + "\n" +
			"sl.u.ABCDefghijklmnopqrstuvwxyz0123456789-_ABCDefghijklmnopqrstuvwxyz",
		want: []veles.Secret{
			dropboxappaccesstoken.APIAccessToken{Token: validToken},
			dropboxappaccesstoken.APIAccessToken{Token: "sl.u.ABCDefghijklmnopqrstuvwxyz0123456789-_ABCDefghijklmnopqrstuvwxyz"},
		},
	}, {
		name:  "dropbox_token_in_curl_command",
		input: `curl -X POST "https://api.dropboxapi.com/2/users/get_current_account" --header "Authorization: Bearer ` + validToken + `"`,
		want: []veles.Secret{
			dropboxappaccesstoken.APIAccessToken{Token: validToken},
		},
	}, {
		name:  "long_dropbox_token",
		input: "sl.u.AGRu-v0jufTn6fQRX1rY400Kx6oey8q6W6eh2ZOTtAn2P8756KRz77uDov18PWbWoMf1tggrceuFSJ7H6NKtUiZPLu3Rp9d-jZiOuHOCTYvTmdvphmTEjweW_0sNK24rl5NxMxFcVJC_D4tlNqtQ6P0UB2r_yF_NmNWrVeJQHWjDOLvW8LlOOQQ8rbAubbQRzngUBrG5ukrG8ZCzUjC3_LWICmn1Pno5Kan6WqyEAF_PWMUn_Pb3fC-mZvpYO1VjcvnlFp5iZNsYuJUfnlxsCxZCYNFW5e5BjnF88ijZDpdYg8BsVLjjzVG47iwHWkqRDvWz5Qrzy6pBVJwx1hI5DmJ5GEr2APVIvJhklb9tktbE9jK4Ge9hXult-WYGFC9mmkndwFu1kVjGvoU9NiuthcY7HP8TbH_1SJigfU1VVuaurLFVHsLFDxDsaDCzVIhVZDoaf5vwuaDgfbgWjvunmrC_sfjR-7kQ3xIqoNFCXrw7G_Xke9JhAEmHe4h-UxlPUy81KSpStojJd92oHNwqwPJXojbpFKYfizlwD42VHZA_AP7sY3G2dsojSBS4N1k5L6TPbUBZPqu14D652ZI37Os820sN_107Bc24SV91TGhqT7JKGSMMiap5EYjnY0jryFMxB-uvjrga-L62_yOIgrGKMAvKIM1_epbYFvxDad3oddiINnJ_inMVOoiovsBn_EyE5tCd0h2ooX_mt_sVwtFU4hxkm4MbLVRRQyIj6twZ_lkX0iPAauwYn0Rk0jb1ZGojWgSDOCNdHKjmXWWJXS2gWv5XU8QJQ3DcKlUOL72ksKplXjv7qJuysS996KggnepOKwk9z2HGIVzWb_1GA1f_DNRcIxdY9p5awnGLeUG31jTCQu4VXUVc9H3Nh7PYe3bHzu-xkK4f3ZCu0fBddp8c4fq3TStxEPtqHz8vVEt10lAL3D_9S-_VLxGFTfqdNQs9h4PRvdjihEvkHqeUFsjqyjeIlWWLf89Tp60OI9mhR6zBRka663xJhs2MGxxKt9VtaT_Gg7ODHWKoxCQsqXO2ikKYrzYjBdqEEQGCOAQUPhFbbBEoklCJy2yayw7LPeCMRjvatp2ss4nKWRiQ6c5ID5_MrRppzl6_Jlw9zCNy0UfzkooK_FcwRNiGtrTmg3exj4HXD5b9QomdjvrOPEuZGVpCqQao8JCZtHATWqh5y8CqYFuwkkQYCiS0dXRFeMGIFjYSa-25ssOTjZfn_6E3C9GQmiI-U-kD4uNHlO_b4GvyKzpk_OW30TjdCbWX4f5onf4bbJWzshQS32GGAJtHsdJmSdHcQ-NhCwLMzozOFNTY5Hd0huKoDLAlI4dElcuo2YJFvRnHulpcsrfaBygGlED2qRQ-FAWvUF7RgpWqndZH9-sRod7eEKfJhXqBCEwmvEJBIe3BNoNW89anOl0x",
		want: []veles.Secret{
			dropboxappaccesstoken.APIAccessToken{Token: "sl.u.AGRu-v0jufTn6fQRX1rY400Kx6oey8q6W6eh2ZOTtAn2P8756KRz77uDov18PWbWoMf1tggrceuFSJ7H6NKtUiZPLu3Rp9d-jZiOuHOCTYvTmdvphmTEjweW_0sNK24rl5NxMxFcVJC_D4tlNqtQ6P0UB2r_yF_NmNWrVeJQHWjDOLvW8LlOOQQ8rbAubbQRzngUBrG5ukrG8ZCzUjC3_LWICmn1Pno5Kan6WqyEAF_PWMUn_Pb3fC-mZvpYO1VjcvnlFp5iZNsYuJUfnlxsCxZCYNFW5e5BjnF88ijZDpdYg8BsVLjjzVG47iwHWkqRDvWz5Qrzy6pBVJwx1hI5DmJ5GEr2APVIvJhklb9tktbE9jK4Ge9hXult-WYGFC9mmkndwFu1kVjGvoU9NiuthcY7HP8TbH_1SJigfU1VVuaurLFVHsLFDxDsaDCzVIhVZDoaf5vwuaDgfbgWjvunmrC_sfjR-7kQ3xIqoNFCXrw7G_Xke9JhAEmHe4h-UxlPUy81KSpStojJd92oHNwqwPJXojbpFKYfizlwD42VHZA_AP7sY3G2dsojSBS4N1k5L6TPbUBZPqu14D652ZI37Os820sN_107Bc24SV91TGhqT7JKGSMMiap5EYjnY0jryFMxB-uvjrga-L62_yOIgrGKMAvKIM1_epbYFvxDad3oddiINnJ_inMVOoiovsBn_EyE5tCd0h2ooX_mt_sVwtFU4hxkm4MbLVRRQyIj6twZ_lkX0iPAauwYn0Rk0jb1ZGojWgSDOCNdHKjmXWWJXS2gWv5XU8QJQ3DcKlUOL72ksKplXjv7qJuysS996KggnepOKwk9z2HGIVzWb_1GA1f_DNRcIxdY9p5awnGLeUG31jTCQu4VXUVc9H3Nh7PYe3bHzu-xkK4f3ZCu0fBddp8c4fq3TStxEPtqHz8vVEt10lAL3D_9S-_VLxGFTfqdNQs9h4PRvdjihEvkHqeUFsjqyjeIlWWLf89Tp60OI9mhR6zBRka663xJhs2MGxxKt9VtaT_Gg7ODHWKoxCQsqXO2ikKYrzYjBdqEEQGCOAQUPhFbbBEoklCJy2yayw7LPeCMRjvatp2ss4nKWRiQ6c5ID5_MrRppzl6_Jlw9zCNy0UfzkooK_FcwRNiGtrTmg3exj4HXD5b9QomdjvrOPEuZGVpCqQao8JCZtHATWqh5y8CqYFuwkkQYCiS0dXRFeMGIFjYSa-25ssOTjZfn_6E3C9GQmiI-U-kD4uNHlO_b4GvyKzpk_OW30TjdCbWX4f5onf4bbJWzshQS32GGAJtHsdJmSdHcQ-NhCwLMzozOFNTY5Hd0huKoDLAlI4dElcuo2YJFvRnHulpcsrfaBygGlED2qRQ-FAWvUF7RgpWqndZH9-sRod7eEKfJhXqBCEwmvEJBIe3BNoNW89anOl0x"},
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

func TestDetector_NoMatches(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{dropboxappaccesstoken.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
	}{{
		name:  "too_short",
		input: "sl.u.tooshort",
	}, {
		name:  "wrong_prefix_no_u",
		input: "sl.ABCDefghijklmnopqrstuvwxyz0123456789ABCDefghijklmnopqrstuvwxyz",
	}, {
		name:  "wrong_prefix_sk",
		input: "sk-proj-abcdefghijklmnopqrstT3BlbkFJuvwxyzABCDEF123456",
	}, {
		name:  "no_secrets",
		input: "This is just regular text with no secrets",
	}, {
		name:  "partial_prefix",
		input: "sl.u.ABCDefghijklmnopqrstuvwxyz0123456789ABCDE",
	}, {
		name:  "sl_prefix_but_not_token",
		input: "sl.something.else.entirely.not.a.token.at.all",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if len(got) != 0 {
				t.Errorf("Detect() got %v secrets, want 0", len(got))
			}
		})
	}
}

func TestDropboxTokenValidation(t *testing.T) {
	testCases := []struct {
		name    string
		key     string
		isValid bool
	}{{
		name:    "valid_dropbox_token",
		key:     validToken,
		isValid: true,
	}, {
		name:    "not_a_token",
		key:     "not-a-token",
		isValid: false,
	}, {
		name:    "empty_string",
		key:     "",
		isValid: false,
	}, {
		name:    "openai_key_format",
		key:     "sk-proj-12345678901234567890T3BlbkFJ12345678901234567890123456",
		isValid: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test by trying to detect the key
			engine, err := veles.NewDetectionEngine([]veles.Detector{dropboxappaccesstoken.NewDetector()})
			if err != nil {
				t.Fatal(err)
			}

			got, err := engine.Detect(t.Context(), strings.NewReader(tc.key))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}

			isDetected := len(got) > 0
			if isDetected != tc.isValid {
				t.Errorf("Key %q detected=%v, want valid=%v",
					tc.key, isDetected, tc.isValid)
			}
		})
	}
}
