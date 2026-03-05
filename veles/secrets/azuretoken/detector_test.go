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

package azuretoken_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/azuretoken"
	"github.com/google/osv-scalibr/veles/velestest"
)

// Valid Azure access/id token with the following issuer:
//   - "https://login.microsoftonline.com/{tenant}/v2.0"
//   - "https://sts.windows.net/{tenant}"
const (
	testAccessTokenMicrosoftIssuer = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSIsImtpZCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC83MmY5ODhiZi04NmYxLTQxYWYtOTFhYi0yZDdjZDAxMWRiNDcvIiwiaWF0IjoxNjk0MTE5MjAwLCJuYmYiOjE2OTQxMTkyMDAsImV4cCI6MTY5NDEyMzEwMCwiYWNyIjoiMSIsImFpbyI6IkFVUUF1LzhVQUFBQWlqVElRWkV5QUc2TXE1Q3U4emdDbElSdldqZmJ4WHJZL0lSb0hDQkZxY0JYeU01dzJkSUxpMzZuWVNLSXlKUWVCMGh5ckx6cTVqWTdqMkVpMnlrOEE9PSIsImFtciI6WyJwd2QiXSwiYXBwaWQiOiIwNGIwNzc5NS04ZGRiLTQ2MWEtYmJlZS0wMmY5ZTFiZjdiNDYiLCJhcHBpZGFjciI6IjAiLCJmYW1pbHlfbmFtZSI6IkRvZSIsImdpdmVuX25hbWUiOiJKb2huIiwiaXBhZGRyIjoiMTk4LjUxLjEwMC4xIiwibmFtZSI6IkpvaG4gRG9lIiwib2lkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLWMwMDAtMDAwMDAwMDAwMDAwIiwib25wcmVtX3NpZCI6IlMtMS01LTIxLTEyMzQ1Njc4OTAtMTIzNDU2Nzg5LTEyMzQ1Njc4OS0xMDAwIiwicmgiOiIwLkFWWUEtNGo1Y3ZHR3IwR1JxeTE4MFFIYlI1VjNzWlRibmhwS3V1NEMtZUc3OSIsInNjcCI6IkZpbGVzLlJlYWQuQWxsIERpcmVjdG9yeS5SZWFkLkFsbCIsInN1YiI6InZJR01mcXREX2V3b2hWS2VvSS1KamFzOHJ4cEJQNTh1WEdPNWJTZm5IaU0iLCJ0ZW5hbnRfcmVnaW9uX3Njb3BlIjoiTkEiLCJ0aWQiOiI3MmY5ODhiZi04NmYxLTQxYWYtOTFhYi0yZDdjZDAxMWRiNDciLCJ1bmlxdWVfbmFtZSI6ImpvaG5kb2VAZXhhbXBsZS5jb20iLCJ1cG4iOiJqb2huZG9lQGV4YW1wbGUuY29tIiwidXRpIjoiVWN6eE1McVNpVVNzTTZGdHlJaFhBUSIsInZlciI6IjEuMCJ9.GJZ9j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5fKJZ2j8qO3X5f"
	testAccessTokenWindowsIssuer   = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSIsImtpZCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20iLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3L3YyLjAiLCJpYXQiOjE2OTQxMTkyMDAsIm5iZiI6MTY5NDExOTIwMCwiZXhwIjoxNjk0MTIzMTAwLCJhY3IiOiIxIiwiYWlvIjoiQVVRQXUvOFVBQUFBaWpUSVFaRXlBRzZNcTVDdTh6Z0NsSVJ2V2pmYnhYclkvSVJvSENCRnFjQlh5TTV3MmRJTGkzNm5ZU0tJeUpRZUIwaHlyTHpxNWpZN2oyRWkyeWs4QT09IiwiYW1yIjpbInB3ZCJdLCJhcHBpZCI6IjA0YjA3Nzk1LThkZGItNDYxYS1iYmVlLTAyZjllMWJmN2I0NiIsImFwcGlkYWNyIjoiMCIsImZhbWlseV9uYW1lIjoiRG9lIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJpcGFkZHIiOiIxOTguNTEuMTAwLjEiLCJuYW1lIjoiSm9obiBEb2UiLCJvaWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtYzAwMC0wMDAwMDAwMDAwMDAiLCJvbnByZW1fc2lkIjoiUy0xLTUtMjEtMTIzNDU2Nzg5MC0xMjM0NTY3ODktMTIzNDU2Nzg5LTEwMDAiLCJyaCI6IjAuQVZZQS00ajVjdkdHcjBHUnF5MTgwUUhiUjVWM3NaVGJuaHBLdXU0Qy1lRzc5Iiwic2NwIjoiRmlsZXMuUmVhZC5BbGwgRGlyZWN0b3J5LlJlYWQuQWxsIiwic3ViIjoidklHTWZxdERfZXdvaFZLZW9JLUpqYXM4cnhwQlA1OHVYR081YlNmbkhpTSIsInRlbmFudF9yZWdpb25fc2NvcGUiOiJOQSIsInRpZCI6IjcyZjk4OGJmLTg2ZjEtNDFhZi05MWFiLTJkN2NkMDExZGI0NyIsInVuaXF1ZV9uYW1lIjoiam9obmRvZUBleGFtcGxlLmNvbSIsInVwbiI6ImpvaG5kb2VAZXhhbXBsZS5jb20iLCJ1dGkiOiJVY3p4TUxxU2lVU3NNNkZ0eUloWEFRIiwidmVyIjoiMS4wIn0.signature"
	testIDTokenMicrosoftIssuer     = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjFMVE16YWtpaGlSbGFfOHoyQkVKVlhlV01xbyJ9.eyJ2ZXIiOiIyLjAiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vOTEyMjA0MGQtNmM2Ny00YzViLWIxMTItMzZhMzA0YjY2ZGFkL3YyLjAiLCJzdWIiOiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFJa3pxRlZyU2FTYUZIeTc4MmJidGFRIiwiYXVkIjoiNmNiMDQwMTgtYTNmNS00NmE3LWI5OTUtOTQwYzc4ZjVhZWYzIiwiZXhwIjoxNTM2MzYxNDExLCJpYXQiOjE1MzYyNzQ3MTEsIm5iZiI6MTUzNjI3NDcxMSwibmFtZSI6IkFiZSBMaW5jb2xuIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQWJlTGlAbWljcm9zb2Z0LmNvbSIsIm9pZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC02NmYzLTMzMzJlY2E3ZWE4MSIsInRpZCI6IjkxMjIwNDBkLTZjNjctNGM1Yi1iMTEyLTM2YTMwNGI2NmRhZCIsIm5vbmNlIjoiMTIzNTIzIiwiYWlvIjoiRGYyVVZYTDFpeCFsTUNXTVNPSkJjRmF0emNHZnZGR2hqS3Y4cTVnMHg3MzJkUjVNQjVCaXN2R1FPN1lXQnlqZDhpUURMcSFlR2JJRGFreXA1bW5PcmNkcUhlWVNubHRlcFFtUnA2QUlaOGpZIn0.1AFWW-Ck5nROwSlltm7GzZvDwUkqvhSQpm55TQsmVo9Y59cLhRXpvB8n-55HCr9Z6G_31_UbeUkoz612I2j_Sm9FFShSDDjoaLQr54CreGIJvjtmS3EkK9a7SJBbcpL1MpUtlfygow39tFjY7EVNW9plWUvRrTgVk7lYLprvfzw-CIqw3gHC-T7IK_m_xkr08INERBtaecwhTeN4chPC4W3jdmw_lIxzC48YoQ0dB1L9-ImX98Egypfrlbm0IBL5spFzL6JDZIRRJOu8vecJvj1mq-IUhGt0MacxX8jdxYLP-KUu2d9MbNKpCKJuZ7p8gwTL5B7NlUdh_dmSviPWrw"
	testIDTokenWindowsIssuer       = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjdfWnVmMXR2a3dMeFlhSFMzcTZsVWpVWUlHdyIsImtpZCI6IjdfWnVmMXR2a3dMeFlhSFMzcTZsVWpVWUlHdyJ9.eyJhdWQiOiJiMTRhNzUwNS05NmU5LTQ5MjctOTFlOC0wNjAxZDBmYzljYWEiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9mYTE1ZDY5Mi1lOWM3LTQ0NjAtYTc0My0yOWYyOTU2ZmQ0MjkvIiwiaWF0IjoxNTM2Mjc1MTI0LCJuYmYiOjE1MzYyNzUxMjQsImV4cCI6MTUzNjI3OTAyNCwiYWlvIjoiQVhRQWkvOElBQUFBcXhzdUIrUjREMnJGUXFPRVRPNFlkWGJMRDlrWjh4ZlhhZGVBTTBRMk5rTlQ1aXpmZzN1d2JXU1hodVNTajZVVDVoeTJENldxQXBCNWpLQTZaZ1o5ay9TVTI3dVY5Y2V0WGZMT3RwTnR0Z2s1RGNCdGsrTExzdHovSmcrZ1lSbXY5YlVVNFhscGhUYzZDODZKbWoxRkN3PT0iLCJhbXIiOlsicnNhIl0sImVtYWlsIjoiYWJlbGlAbWljcm9zb2Z0LmNvbSIsImZhbWlseV9uYW1lIjoiTGluY29sbiIsImdpdmVuX25hbWUiOiJBYmUiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC83MmY5ODhiZi04NmYxLTQxYWYtOTFhYi0yZDdjZDAxMWRiNDcvIiwiaXBhZGRyIjoiMTMxLjEwNy4yMjIuMjIiLCJuYW1lIjoiYWJlbGkiLCJub25jZSI6IjEyMzUyMyIsIm9pZCI6IjA1ODMzYjZiLWFhMWQtNDJkNC05ZWMwLTFiMmJiOTE5NDQzOCIsInJoIjoiSSIsInN1YiI6IjVfSjlyU3NzOC1qdnRfSWN1NnVlUk5MOHhYYjhMRjRGc2dfS29vQzJSSlEiLCJ0aWQiOiJmYTE1ZDY5Mi1lOWM3LTQ0NjAtYTc0My0yOWYyOTU2ZmQ0MjkiLCJ1bmlxdWVfbmFtZSI6IkFiZUxpQG1pY3Jvc29mdC5jb20iLCJ1dGkiOiJMeGVfNDZHcVRrT3BHU2ZUbG40RUFBIiwidmVyIjoiMS4wIn0.UJQrCA6qn2bXq57qzGX_-D3HcPHqBMOKDPx4su1yKRLNErVD8xkxJLNLVRdASHqEcpyDctbdHccu6DPpkq5f0ibcaQFhejQNcABidJCTz0Bb2AbdUCTqAzdt9pdgQvMBnVH1xk3SCM6d4BbT4BkLLj10ZLasX7vRknaSjE_C5DI7Fg4WrZPwOhII1dB0HEZ_qpNaYXEiy-o94UJ94zCr07GgrqMsfYQqFR7kn-mn68AjvLcgwSfZvyR_yIK75S_K37vC3QryQ7cNoafDe9upql_6pB2ybMVlgWPs_DmbJ8g0om-sPlwyn74Cc1tW3ze-Xptw_2uVdPgWyqfuWAfq6Q"
)

func TestDetectorAcceptance(t *testing.T) {
	d := azuretoken.NewDetector()
	cases := []struct {
		name   string
		token  string
		secret veles.Secret
	}{
		{
			name:   "access-token-microsoft",
			token:  testAccessTokenMicrosoftIssuer,
			secret: azuretoken.AzureAccessToken{Token: testAccessTokenMicrosoftIssuer},
		},
		{
			name:   "access-token-windows",
			token:  testAccessTokenWindowsIssuer,
			secret: azuretoken.AzureAccessToken{Token: testAccessTokenWindowsIssuer},
		},
		{
			name:   "identity-token-microsoft",
			token:  testIDTokenMicrosoftIssuer,
			secret: azuretoken.AzureIdentityToken{Token: testIDTokenMicrosoftIssuer},
		},
		{
			name:   "identity-token-windows",
			token:  testIDTokenWindowsIssuer,
			secret: azuretoken.AzureIdentityToken{Token: testIDTokenWindowsIssuer},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			velestest.AcceptDetector(t, d, tc.token, tc.secret)
		})
	}
}

// TestDetector_truePositives tests for cases where we know the Detector
// will find an Azure token.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{azuretoken.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "access token with login.microsoftonline.com issuer",
			input: testAccessTokenMicrosoftIssuer,
			want: []veles.Secret{
				azuretoken.AzureAccessToken{Token: testAccessTokenMicrosoftIssuer},
			},
		},
		{
			name:  "id token with login.microsoftonline.com issuer",
			input: testIDTokenMicrosoftIssuer,
			want: []veles.Secret{
				azuretoken.AzureIdentityToken{Token: testIDTokenMicrosoftIssuer},
			},
		},
		{
			name:  "access token with sts.windows.net issuer",
			input: testAccessTokenWindowsIssuer,
			want: []veles.Secret{
				azuretoken.AzureAccessToken{Token: testAccessTokenWindowsIssuer},
			},
		},
		{
			name:  "id token with sts.windows.net issuer",
			input: testIDTokenWindowsIssuer,
			want: []veles.Secret{
				azuretoken.AzureIdentityToken{Token: testIDTokenWindowsIssuer},
			},
		},
		{
			name:  "access token in middle of text",
			input: "prefix " + testAccessTokenMicrosoftIssuer + " suffix",
			want: []veles.Secret{
				azuretoken.AzureAccessToken{Token: testAccessTokenMicrosoftIssuer},
			},
		},
		{
			name:  "multiple tokens",
			input: testAccessTokenMicrosoftIssuer + " " + testIDTokenMicrosoftIssuer + " " + testIDTokenWindowsIssuer,
			want: []veles.Secret{
				azuretoken.AzureAccessToken{Token: testAccessTokenMicrosoftIssuer},
				azuretoken.AzureIdentityToken{Token: testIDTokenMicrosoftIssuer},
				azuretoken.AzureIdentityToken{Token: testIDTokenWindowsIssuer},
			},
		},
		{
			name:  "access token in long buffer",
			input: strings.Repeat("a", 64*veles.KiB) + " " + testAccessTokenMicrosoftIssuer + " " + strings.Repeat("a", 64*veles.KiB),
			want: []veles.Secret{
				azuretoken.AzureAccessToken{Token: testAccessTokenMicrosoftIssuer},
			},
		},
	}
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
// will not find an Azure token.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{azuretoken.NewDetector()})
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
		name:  "invalid JWT - only header",
		input: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9",
	}, {
		name:  "invalid JWT - malformed payload",
		input: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.invalid-payload.signature",
	}, {
		name:  "JWT without Azure issuer",
		input: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzNCIsIm5hbWUiOiJKb2huIERvZSIsImlhdCI6MTUxNjIzOTAyMn0.signature",
	}, {
		name:  "invalid JWT",
		input: "not.a.jwt",
	}, {
		name:  "token exceeding max length",
		input: strings.Repeat("a", 8193),
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
