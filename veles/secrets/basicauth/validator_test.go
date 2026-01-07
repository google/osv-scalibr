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

package basicauth_test

import (
	"bufio"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/basicauth"
	"golang.org/x/crypto/ssh"
)

func TestValidator(t *testing.T) {
	basicAuthHTTPSvr := mockBasicAuthHTTPServer(t, "admin", "pass")
	digestHTTPSvr := mockDigestHTTPServer(t, "admin", "pass")
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
			v := basicauth.NewValidator()
			got, err := v.Validate(t.Context(), basicauth.Credentials{FullURL: tt.url})

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
				defer c.Close()
				fmt.Fprint(c, "220 Welcome\r\n")

				scanner := bufio.NewScanner(c)
				var user string

				for scanner.Scan() {
					parts := strings.SplitN(strings.TrimSpace(scanner.Text()), " ", 2)
					cmd := strings.ToUpper(parts[0])
					arg := ""
					if len(parts) > 1 {
						arg = parts[1]
					}

					switch cmd {
					case "USER":
						user = arg
						fmt.Fprint(c, "331 Password required\r\n")
					case "PASS":
						if user == validUser && arg == validPass {
							fmt.Fprint(c, "230 Logged in\r\n")
						} else {
							fmt.Fprint(c, "530 Login incorrect\r\n")
						}
					case "QUIT":
						fmt.Fprint(c, "221 Goodbye\r\n")
						return
					default:
						fmt.Fprint(c, "502 Command not implemented\r\n")
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

	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
func mockDigestHTTPServer(t *testing.T, validUser, validPass string) *httptest.Server {
	t.Helper()

	const (
		realm     = "test-realm"
		nonce     = "test-nonce"
		qop       = "auth"
		algorithm = "MD5"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		// If no Authorization header, send the Challenge (401)
		if authHeader == "" {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Digest realm="%s", nonce="%s", algorithm=%s, qop="%s"`,
					realm, nonce, algorithm, qop))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Parse the Client's Authorization Header
		if !strings.HasPrefix(authHeader, "Digest ") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Regex to parse key="value" or key=value
		re := regexp.MustCompile(`([\w-]+)=(?:"([^"]*)"|([^,]*))`)
		matches := re.FindAllStringSubmatch(authHeader[7:], -1) // Skip "Digest "

		params := make(map[string]string)
		for _, m := range matches {
			val := m[2]
			if val == "" {
				val = m[3]
			}
			params[m[1]] = val
		}

		// handle login
		if params["username"] != validUser {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if params["realm"] != realm || params["nonce"] != nonce {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ha1 := md5Sum(fmt.Sprintf("%s:%s:%s", validUser, realm, validPass))
		ha2 := md5Sum(fmt.Sprintf("%s:%s", r.Method, params["uri"]))

		respRaw := fmt.Sprintf("%s:%s:%s:%s:%s:%s",
			ha1, nonce, params["nc"], params["cnonce"], params["qop"], ha2)
		expectedResponse := md5Sum(respRaw)

		// Compare
		if params["response"] != expectedResponse {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Cleanup(server.Close)
	return server
}

// md5Sum is a local helper for the test server
func md5Sum(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}
