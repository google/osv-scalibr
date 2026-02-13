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

package urlcreds_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/urlcreds"
	"golang.org/x/crypto/ssh"
)

func TestValidator(t *testing.T) {
	basicAuthHTTPSvr := mockBasicAuthHTTPServer(t, "admin", "pass")
	digestHTTPSvr := mockDigestHTTPServer(t, "admin", "pass", false)
	digestHTTPSvrWithCookies := mockDigestHTTPServer(t, "admin", "pass", true)
	ftpAddr := mockFTPServer(t, "user", "pass")
	sftpAddr := mockSSHServer(t, "sshuser", "sshpass")

	cases := []struct {
		name    string
		url     string
		want    veles.ValidationStatus
		wantErr error
	}{
		// HTTP Tests
		{
			name: "http_valid",
			url:  fmt.Sprintf("http://admin:pass@%s/resource", basicAuthHTTPSvr.Listener.Addr().String()),
			want: veles.ValidationValid,
		},
		{
			name: "http_invalid",
			url:  fmt.Sprintf("http://admin:wrong@%s/resource", basicAuthHTTPSvr.Listener.Addr().String()),
			want: veles.ValidationInvalid,
		},
		{
			name: "http_valid_digest",
			url:  fmt.Sprintf("http://admin:pass@%s/resource", digestHTTPSvr.Listener.Addr().String()),
			want: veles.ValidationValid,
		},
		{
			name: "http_invalid_digest",
			url:  fmt.Sprintf("http://admin:wrong@%s/resource", digestHTTPSvr.Listener.Addr().String()),
			want: veles.ValidationInvalid,
		},
		{
			name: "http_valid_digest_with_set_cookie",
			url:  fmt.Sprintf("http://admin:pass@%s/resource", digestHTTPSvrWithCookies.Listener.Addr().String()),
			want: veles.ValidationValid,
		},
		{
			name: "http_invalid_digest_with_set_cookie",
			url:  fmt.Sprintf("http://admin:wrong@%s/resource", digestHTTPSvrWithCookies.Listener.Addr().String()),
			want: veles.ValidationInvalid,
		},
		// FTP Tests
		{
			name: "ftp_valid",
			url:  fmt.Sprintf("ftp://user:pass@%s/files", ftpAddr),
			want: veles.ValidationValid,
		},
		{
			name: "ftp_invalid",
			url:  fmt.Sprintf("ftp://user:wrong@%s/files", ftpAddr),
			want: veles.ValidationInvalid,
		},
		// SFTP Tests
		{
			name: "sftp_valid",
			url:  "sftp://sshuser:sshpass@" + sftpAddr,
			want: veles.ValidationValid,
		},
		{
			name: "sftp_invalid",
			url:  "sftp://sshuser:wrong@" + sftpAddr,
			want: veles.ValidationInvalid,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			v := urlcreds.NewValidator()
			got, err := v.Validate(t.Context(), urlcreds.Credentials{FullURL: tt.url})

			if !cmp.Equal(tt.wantErr, err, cmpopts.EquateErrors()) {
				t.Fatalf("Validate() error: %v, want %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Validate() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func mockFTPServer(t *testing.T, validUser, validPass string) string {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { l.Close() })

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return // Listener closed by t.Cleanup
			}
			go func(c net.Conn) {
				tc := textproto.NewConn(c)
				defer tc.Close()

				_ = tc.PrintfLine("220 Welcome")

				var user string

				for {
					line, err := tc.ReadLine()
					if err != nil {
						return
					}

					parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
					cmd := strings.ToUpper(parts[0])
					arg := ""
					if len(parts) > 1 {
						arg = parts[1]
					}

					switch cmd {
					case "USER":
						user = arg
						_ = tc.PrintfLine("331 Password required")
					case "PASS":
						if user == validUser && arg == validPass {
							_ = tc.PrintfLine("230 Logged in")
						} else {
							_ = tc.PrintfLine("530 Login incorrect")
						}
					case "QUIT":
						_ = tc.PrintfLine("221 Goodbye")
						return
					default:
						_ = tc.PrintfLine("502 Command not implemented")
					}
				}
			}(conn)
		}
	}()
	return l.Addr().String()
}

func mockSSHServer(t *testing.T, validUser, validPass string) string {
	t.Helper()
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == validUser && string(pass) == validPass {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config.AddHostKey(signer)

	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// Perform the SSH handshake
				sConn, _, _, err := ssh.NewServerConn(c, config)
				if err == nil {
					sConn.Close()
				}
			}(conn)
		}
	}()
	return l.Addr().String()
}

func mockBasicAuthHTTPServer(t *testing.T, validUser, validPass string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || !(u == validUser && p == validPass) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() { server.Close() })
	return server
}

// mockDigestHTTPServer creates a test server that enforces Digest Authentication.
func mockDigestHTTPServer(t *testing.T, validUser, validPass string, testCookies bool) *httptest.Server {
	t.Helper()

	sha256Sum := func(text string) string {
		hash := sha256.Sum256([]byte(text))
		return hex.EncodeToString(hash[:])
	}

	const (
		realm     = "test-realm"
		nonce     = "test-nonce"
		qop       = "auth"
		algorithm = "SHA-256"
	)

	const (
		cookieName  = "test-cookie"
		cookieValue = "test-cookie-value"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		// If no Authorization header, send the Challenge (401)
		if authHeader == "" {
			w.Header().Set(
				"WWW-Authenticate", fmt.Sprintf(
					`Digest realm="%s", nonce="%s", algorithm=%s, qop="%s"`,
					realm, nonce, algorithm, qop,
				),
			)
			if testCookies {
				http.SetCookie(w, &http.Cookie{
					Name:  cookieName,
					Value: cookieValue,
					Path:  "/",
				})
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// If  enabled check that the client uses the given cookies
		if testCookies {
			c, err := r.Cookie(cookieName)
			if err != nil || c.Value != cookieValue {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}

		// Parse the parameter
		content, ok := strings.CutPrefix(authHeader, "Digest ")
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		params := make(map[string]string)
		for pair := range strings.SplitSeq(content, ",") {
			if k, v, ok := strings.Cut(strings.TrimSpace(pair), "="); ok {
				params[k] = strings.Trim(v, `"`)
			}
		}

		// Handle login
		if params["username"] != validUser || params["realm"] != realm || params["nonce"] != nonce {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ha1 := sha256Sum(fmt.Sprintf("%s:%s:%s", validUser, realm, validPass))
		ha2 := sha256Sum(fmt.Sprintf("%s:%s", r.Method, params["uri"]))

		expectedResponse := sha256Sum(fmt.Sprintf("%s:%s:%s:%s:%s:%s",
			ha1, nonce, params["nc"], params["cnonce"], params["qop"], ha2))

		if params["response"] != expectedResponse {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Cleanup(server.Close)
	return server
}
