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
	testSAPAccessToken     = "access_token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmaWdhZnBhcnRuZXItMS5pdC1jcGkwMTguY2ZhcHBzLmV1MTAtMDAzLmhhbmEub25kZW1hbmQuY29tIiwiY2lkIjoic2ItY2ZmYzQxOTctZTJiYi00YTgyLWExMjctOGYyMDJhM2JiNDVjIWIxNTc5Nzh8aXQhYjExNzkxMiJ9.signature"
	testSAPURL             = "url: figafpartner-1.it-cpi018.cfapps.eu10-003.hana.ondemand.com"
	expectedSAPAccessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmaWdhZnBhcnRuZXItMS5pdC1jcGkwMTguY2ZhcHBzLmV1MTAtMDAzLmhhbmEub25kZW1hbmQuY29tIiwiY2lkIjoic2ItY2ZmYzQxOTctZTJiYi00YTgyLWExMjctOGYyMDJhM2JiNDVjIWIxNTc5Nzh8aXQhYjExNzkxMiJ9.signature"
	expectedSAPURL         = "figafpartner-1.it-cpi018.cfapps.eu10-003.hana.ondemand.com"
)

func detectors() map[string]veles.Detector {
	return map[string]veles.Detector{
		"BTPXSUAA": sap.NewBTPXSUAAAccessTokenDetector(),
		"BTP":      sap.NewBTPAccessTokenDetector(),
	}
}

func TestSAPBTPAccessTokenDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		sap.NewBTPAccessTokenDetector(),
		testSAPAccessToken+"\n"+testSAPURL,
		sap.AccessToken{Token: expectedSAPAccessToken, URL: expectedSAPURL},
	)
}

func TestSAPBTPXSUAAAccessTokenDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		sap.NewBTPXSUAAAccessTokenDetector(),
		testSAPAccessToken+"\n"+testSAPURL,
		sap.AccessToken{Token: expectedSAPAccessToken, URL: expectedSAPURL},
	)
}

func TestDetector_truePositives(t *testing.T) {
	for name, detector := range detectors() {
		t.Run(name, func(t *testing.T) {
			engine, err := veles.NewDetectionEngine([]veles.Detector{detector})
			if err != nil {
				t.Fatal(err)
			}

			cases := []struct {
				name  string
				input string
				want  []veles.Secret
			}{
				{
					name:  "valid SAP credentials",
					input: testSAPAccessToken + "\n" + testSAPURL,
					want: []veles.Secret{
						sap.AccessToken{
							Token: expectedSAPAccessToken,
							URL:   expectedSAPURL,
						},
					},
				},
				{
					name:  "Credentials in middle of text",
					input: "prefix " + testSAPAccessToken + "\n" + testSAPURL + " suffix",
					want: []veles.Secret{
						sap.AccessToken{
							Token: expectedSAPAccessToken,
							URL:   expectedSAPURL,
						},
					},
				},
				{
					name:  "multiple tokens",
					input: testSAPAccessToken + "\n" + testSAPURL + "\n" + testSAPAccessToken + "\n" + testSAPURL,
					want: []veles.Secret{
						sap.AccessToken{
							Token: expectedSAPAccessToken,
							URL:   expectedSAPURL,
						},
						sap.AccessToken{
							Token: expectedSAPAccessToken,
							URL:   expectedSAPURL,
						},
					},
				},
				{
					name:  "Credentials in long buffer",
					input: strings.Repeat("a", 64*veles.KiB) + " " + testSAPAccessToken + "\n" + testSAPURL,
					want: []veles.Secret{
						sap.AccessToken{
							Token: expectedSAPAccessToken,
							URL:   expectedSAPURL,
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
		})
	}
}

func TestDetector_trueNegatives(t *testing.T) {
	for name, detector := range detectors() {
		t.Run(name, func(t *testing.T) {
			engine, err := veles.NewDetectionEngine([]veles.Detector{detector})
			if err != nil {
				t.Fatal(err)
			}

			cases := []struct {
				name  string
				input string
				want  []veles.Secret
			}{
				{
					name:  "empty input",
					input: "",
				},
				{
					name:  "invalid JWT header only",
					input: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9" + "\n" + testSAPURL,
				},
				{
					name:  "malformed payload",
					input: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.invalid-payload.signature" + "\n" + testSAPURL,
				},
				{
					name:  "malformed url",
					input: testSAPAccessToken + "\n" + "cfapp.hana.ondemanded.com",
				},
				{
					name:  "missing issuer",
					input: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJjaWQiOiJzYi1jZmZjNDE5Ny1lMmJiLTRhODItYTEyNy04ZjIwMmEzYmI0NWMhYjE1Nzk3OHxpdCFiMTE3OTEyIn0.signature" + "\n" + testSAPURL,
				},
				{
					name:  "missing cid",
					input: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmaWdhZnBhcnRuZXItMS5pdC1jcGkwMTguY2ZhcHBzLmV1MTAtMDAzLmhhbmEub25kZW1hbmQuY29tIn0.signature" + "\n" + testSAPURL,
				},
				{
					name:  "missing url",
					input: testSAPAccessToken,
				},
				{
					name:  "not a jwt",
					input: "not.a.jwt",
				},
				{
					name:  "token exceeding max length",
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
		})
	}
}
