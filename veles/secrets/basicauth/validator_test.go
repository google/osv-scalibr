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
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/basicauth"
	"golang.org/x/crypto/ssh"
)

func TestValidator(t *testing.T) {
	httpSvr := mockHTTPServer(t, "admin", "pass")
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
			url:  fmt.Sprintf("http://admin:pass@%s/resource", httpSvr.Listener.Addr().String()),
			want: veles.ValidationValid,
		},
		{
			name: "http_invalid",
			url:  fmt.Sprintf("http://admin:wrong@%s/resource", httpSvr.Listener.Addr().String()),
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
			url:  "sftp://sshuser:wrong@%s" + sftpAddr,
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
					// 2. Use SplitN to handle passwords with spaces and commands without args
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
						// 3. Prevent client hangs on commands like SYST or FEAT
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

func mockHTTPServer(t *testing.T, validUser, validPass string) *httptest.Server {
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
