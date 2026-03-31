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
	"crypto/md5"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/mongodbatlasapikey"
)

type mockRoundTripper struct {
	url string
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "cloud.mongodb.com" {
		testURL, _ := url.Parse(m.url)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

const (
	validPublicKey  = "yhrqvogk"
	validPrivateKey = "f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97"
	testRealm       = "MMS Public API"
	testNonce       = "testnonce123"
)

func md5Hex(s string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(s)))
}

// verifyDigestAuth checks a Digest Authorization header against expected credentials.
func verifyDigestAuth(authHeader, expectedUser, expectedPass string) bool {
	if !strings.HasPrefix(authHeader, "Digest ") {
		return false
	}

	params := make(map[string]string)
	for _, part := range strings.Split(strings.TrimPrefix(authHeader, "Digest "), ",") {
		part = strings.TrimSpace(part)
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		params[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
	}

	username := params["username"]
	nonce := params["nonce"]
	nc := params["nc"]
	cnonce := params["cnonce"]
	qop := params["qop"]
	uri := params["uri"]
	response := params["response"]

	if username != expectedUser {
		return false
	}

	ha1 := md5Hex(username + ":" + testRealm + ":" + expectedPass)
	ha2 := md5Hex("GET:" + uri)

	var expected string
	if qop == "auth" || qop == "auth-int" {
		expected = md5Hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
	} else {
		expected = md5Hex(ha1 + ":" + nonce + ":" + ha2)
	}

	return response == expected
}

// mockAtlasServer creates a test server that simulates MongoDB Atlas Digest Auth.
func mockAtlasServer(statusOnAuth int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			// Step 1: Return Digest challenge.
			w.Header().Set("Www-Authenticate", fmt.Sprintf(
				`Digest realm="%s", nonce="%s", qop="auth"`, testRealm, testNonce))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Step 2: Verify credentials.
		if verifyDigestAuth(auth, validPublicKey, validPrivateKey) {
			w.WriteHeader(statusOnAuth)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name   string
		key    mongodbatlasapikey.Credentials
		want   veles.ValidationStatus
		server *httptest.Server
	}{
		{
			name: "valid_credentials",
			key: mongodbatlasapikey.Credentials{
				PublicKey:  validPublicKey,
				PrivateKey: validPrivateKey,
			},
			want:   veles.ValidationValid,
			server: mockAtlasServer(http.StatusOK),
		},
		{
			name: "invalid_public_key",
			key: mongodbatlasapikey.Credentials{
				PublicKey:  "badpubky",
				PrivateKey: validPrivateKey,
			},
			want:   veles.ValidationInvalid,
			server: mockAtlasServer(http.StatusOK),
		},
		{
			name: "invalid_private_key",
			key: mongodbatlasapikey.Credentials{
				PublicKey:  validPublicKey,
				PrivateKey: "00000000-0000-0000-0000-000000000000",
			},
			want:   veles.ValidationInvalid,
			server: mockAtlasServer(http.StatusOK),
		},
		{
			name: "forbidden_but_authenticated",
			key: mongodbatlasapikey.Credentials{
				PublicKey:  validPublicKey,
				PrivateKey: validPrivateKey,
			},
			want:   veles.ValidationValid,
			server: mockAtlasServer(http.StatusForbidden),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer tc.server.Close()
			client := &http.Client{
				Transport: &mockRoundTripper{url: tc.server.URL},
			}

			validator := mongodbatlasapikey.NewValidator()
			validator.SetHTTPClient(client)

			got, err := validator.Validate(t.Context(), tc.key)
			if err != nil {
				t.Errorf("Validate() error: %v, want nil", err)
			}
			if got != tc.want {
				t.Errorf("Validate() = %q, want %q", got, tc.want)
			}
		})
	}
}
