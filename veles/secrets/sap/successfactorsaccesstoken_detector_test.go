package sap_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/sap"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	testSAPSuccessFactorsAccessToken     = "access_token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJzYXBzZi5jb20iLCJjaWQiOiJ0ZXN0LWNsaWVudC0xMjMiLCJzdWIiOiJ0ZXN0LXVzZXIifQ.signature"
	expectedSAPSuccessFactorsAccessToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJzYXBzZi5jb20iLCJjaWQiOiJ0ZXN0LWNsaWVudC0xMjMiLCJzdWIiOiJ0ZXN0LXVzZXIifQ.signature"
)

func TestSAPSuccessFactorsAccessTokenDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		sap.NewSAPSuccessFactorsAccessTokenDetector(),
		testSAPSuccessFactorsAccessToken,
		sap.SuccessFactorsAccessToken{Token: expectedSAPSuccessFactorsAccessToken},
	)
}

func TestSuccessFactorsAccessTokenDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{sap.NewSAPSuccessFactorsAccessTokenDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "valid_SAP_credentials",
			input: testSAPSuccessFactorsAccessToken + "\n" + testSAPURL,
			want: []veles.Secret{
				sap.SuccessFactorsAccessToken{
					Token: expectedSAPSuccessFactorsAccessToken,
				},
			},
		},
		{
			name:  "Credentials_in_middle_of_text",
			input: "prefix " + testSAPSuccessFactorsAccessToken + "\n" + testSAPURL + " suffix",
			want: []veles.Secret{
				sap.SuccessFactorsAccessToken{
					Token: expectedSAPSuccessFactorsAccessToken,
				},
			},
		},
		{
			name:  "multiple_tokens",
			input: testSAPSuccessFactorsAccessToken + "\n" + testSAPSuccessFactorsAccessToken,
			want: []veles.Secret{
				sap.SuccessFactorsAccessToken{
					Token: expectedSAPSuccessFactorsAccessToken,
				},
				sap.SuccessFactorsAccessToken{
					Token: expectedSAPSuccessFactorsAccessToken,
				},
			},
		},
		{
			name:  "Token_in_long_buffer",
			input: strings.Repeat("a", 64*veles.KiB) + " " + testSAPSuccessFactorsAccessToken,
			want: []veles.Secret{
				sap.SuccessFactorsAccessToken{
					Token: expectedSAPSuccessFactorsAccessToken,
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v", err)
			}

			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSuccessFactorsAccessTokenDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{sap.NewSAPSuccessFactorsAccessTokenDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "empty_input",
			input: "",
		},
		{
			name:  "invalid_JWT_header_only",
			input: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9",
		},
		{
			name:  "malformed_payload",
			input: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.invalid-payload.signature",
		},
		{
			name:  "missing_issuer",
			input: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJjaWQiOiJzYi1jZmZjNDE5Ny1lMmJiLTRhODItYTEyNy04ZjIwMmEzYmI0NWMhYjE1Nzk3OHxpdCFiMTE3OTEyIn0.signature",
		},
		{
			name:  "missing_cid",
			input: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmaWdhZnBhcnRuZXItMS5pdC1jcGkwMTguY2ZhcHBzLmV1MTAtMDAzLmhhbmEub25kZW1hbmQuY29tIn0.signature",
		},
		{
			name:  "not_a_jwt",
			input: "not.a.jwt",
		},
		{
			name:  "token_exceeding_max_length",
			input: strings.Repeat("a", 8193),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v", err)
			}

			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
