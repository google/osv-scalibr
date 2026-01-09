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

package httpauth_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/veles/secrets/urlcreds/validators/httpauth"
)

func TestSetDigestAuth(t *testing.T) {
	testUser := url.UserPassword("admin", "secret")

	tests := []struct {
		name           string
		method         string
		uri            string
		challenge      string // The WWW-Authenticate header from server
		cNonce         string // 0000000000000000 as default
		wantErr        bool
		wantAuthHeader string
	}{
		{
			name:           "standard_md5_with_qop",
			method:         http.MethodGet,
			uri:            "/something",
			challenge:      `Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"`,
			wantAuthHeader: `Digest username="admin", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/something", response="4d31bc891aab3e0084a8ee22038a32e8", opaque="5ccc069c403ebaf9f0171e9517f40e41", qop=auth, nc=00000001, cnonce="0000000000000000"`,
		},
		{
			name:           "sha-256",
			method:         http.MethodGet,
			uri:            "/something",
			challenge:      `Digest realm="testrealm@host.com", qop="auth", algorithm=SHA-256, nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"`,
			wantAuthHeader: `Digest username="admin", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/something", response="0df6c9cd6d7d700b4ce0d95326178e0ceebda3c72bb34ec81c935cd741ebdf15", algorithm=SHA-256, opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS", qop=auth, nc=00000001, cnonce="0000000000000000"`,
		},
		{
			name:           "legacy_mode",
			method:         http.MethodGet,
			uri:            "/something",
			challenge:      `Digest realm="legacy@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093"`,
			wantAuthHeader: `Digest username="admin", realm="legacy@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/something", response="4901cf5014cdbd375ebcfcf643daa2df"`,
		},
		{
			name:      "invalid_prefix",
			method:    http.MethodGet,
			uri:       "/something",
			challenge: `Basic realm="WallyWorld"`,
			wantErr:   true,
		},
		{
			name:      "unsupported_algorithm",
			method:    http.MethodGet,
			uri:       "/something",
			challenge: `Digest realm="foo", nonce="bar", algorithm=SHA-512`,
			wantErr:   true,
		},
		{
			name:      "unsupported_method",
			method:    http.MethodPost,
			uri:       "/something",
			challenge: `Digest realm="legacy@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093"`,
			wantErr:   true,
		},
		{
			// values for this testcase were generated as follow:
			// 1. Launch a mock server using flask and flask_httpauth.HTTPDigestAuth as authentication
			// 2. Use curl to log client-server interactions:
			// 	```
			// 	curl -c cookies.txt --digest -u admin:secret http://localhost:5000/ -v to retrieve values
			// 	```
			name:           "curl_and_flask_httpauth_server",
			method:         http.MethodGet,
			uri:            "/",
			challenge:      `Digest realm="legacy@host.com",nonce="de0e2b959d1bdbfc81444386dbdbe8ca",opaque="ce2ea406520dca912edb53ea3a0abe73",algorithm="MD5",qop="auth"`,
			wantAuthHeader: `Digest username="admin", realm="legacy@host.com", nonce="de0e2b959d1bdbfc81444386dbdbe8ca", uri="/", cnonce="NGFjMTRlNzVjZDQ4ZjQ5NTVhNGYxNzZmYWQyMGUzZTA=", nc=00000001, qop=auth, response="9f5e1779686db2de0ce81a8a3d3b7d30", opaque="ce2ea406520dca912edb53ea3a0abe73", algorithm=MD5`,
			cNonce:         `NGFjMTRlNzVjZDQ4ZjQ5NTVhNGYxNzZmYWQyMGUzZTA=`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cNonce == "" {
				tt.cNonce = "0000000000000000"
			}
			req, _ := http.NewRequestWithContext(t.Context(), tt.method, "http://localhost"+tt.uri, nil)
			err := httpauth.SetDigestAuthWithNonce(req, testUser, tt.challenge, tt.cNonce)

			if (err != nil) != tt.wantErr {
				t.Errorf("SetDigestAuth() error = '%v', wantErr '%v'", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			authHeader := req.Header.Get("Authorization")
			gotMap := parseDigest(authHeader)
			wantMap := parseDigest(tt.wantAuthHeader)

			if !cmp.Equal(gotMap, wantMap) {
				t.Errorf("SetDigestAuth() Authorization = '%v', wantAuthorization '%v'", authHeader, tt.wantAuthHeader)
			}
		})
	}
}

// parseDigest parses the digest header, for test purposes only, do not use in production.
func parseDigest(header string) map[string]string {
	headerVal, ok := strings.CutPrefix(header, "Digest ")
	if !ok {
		return nil
	}
	m := make(map[string]string)
	for part := range strings.SplitSeq(headerVal, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			m[kv[0]] = strings.Trim(kv[1], `"`)
		}
	}
	return m
}
