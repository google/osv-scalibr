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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
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
	amqpAddr := mockAMQPServer(t, "mquser", "mqpass")

	cases := []struct {
		name string
		url  string
		want veles.ValidationStatus
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
		// AMQP Tests
		{
			name: "amqp_valid",
			url:  fmt.Sprintf("amqp://mquser:mqpass@%s/", amqpAddr),
			want: veles.ValidationValid,
		},
		{
			name: "amqp_invalid",
			url:  fmt.Sprintf("amqp://mquser:wrong@%s/", amqpAddr),
			want: veles.ValidationInvalid,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			v := urlcreds.NewValidator()
			got, err := v.Validate(t.Context(), urlcreds.Credentials{FullURL: tt.url})

			if err != nil {
				t.Fatalf("Validate(): %v", err)
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

// mockAMQPServer creates a minimal AMQP 0-9-1 server that validates credentials via SASL PLAIN.
func mockAMQPServer(t *testing.T, validUser, validPass string) string {
	t.Helper()

	const (
		classConnection = 10
		methodStart     = 10
		methodStartOK   = 11
		methodTune      = 30
		methodClose     = 50
	)

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
				defer c.Close()

				// Read AMQP protocol header (8 bytes: "AMQP" + 4 version bytes).
				header := make([]byte, 8)
				if _, err := io.ReadFull(c, header); err != nil {
					return
				}
				if string(header[:4]) != "AMQP" {
					return
				}

				// Send Connection.Start.
				if err := amqpWriteMethodFrame(c, methodStart, amqpConnectionStartPayload()); err != nil {
					return
				}

				// Read Connection.Start-Ok.
				classID, methodID, payload, err := amqpTestReadMethodFrame(c)
				if err != nil || classID != classConnection || methodID != methodStartOK {
					return
				}

				// Parse SASL credentials from the Start-Ok payload.
				user, pass, ok := amqpParseSASLPlain(payload)
				if !ok {
					_ = amqpWriteMethodFrame(c, methodClose, amqpConnectionClosePayload(403, "ACCESS_REFUSED"))
					return
				}

				if user == validUser && pass == validPass {
					// Send Connection.Tune (authentication succeeded).
					_ = amqpWriteMethodFrame(c, methodTune, amqpConnectionTunePayload())
				} else {
					// Send Connection.Close (authentication failed).
					_ = amqpWriteMethodFrame(c, methodClose, amqpConnectionClosePayload(403, "ACCESS_REFUSED"))
				}
			}(conn)
		}
	}()
	return l.Addr().String()
}

// amqpWriteMethodFrame writes a single AMQP Connection-class method frame.
func amqpWriteMethodFrame(w io.Writer, methodID uint16, args []byte) error {
	const classConnection uint16 = 10
	payloadSize := 4 + len(args)
	frame := make([]byte, 7+payloadSize+1)
	frame[0] = 1 // method frame
	binary.BigEndian.PutUint16(frame[1:3], 0)
	binary.BigEndian.PutUint32(frame[3:7], uint32(payloadSize))
	binary.BigEndian.PutUint16(frame[7:9], classConnection)
	binary.BigEndian.PutUint16(frame[9:11], methodID)
	copy(frame[11:], args)
	frame[len(frame)-1] = 0xCE
	_, err := w.Write(frame)
	return err
}

// amqpTestReadMethodFrame reads a single AMQP method frame.
func amqpTestReadMethodFrame(r io.Reader) (classID, methodID uint16, payload []byte, err error) {
	header := make([]byte, 7)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, 0, nil, err
	}
	size := binary.BigEndian.Uint32(header[3:7])
	buf := make([]byte, size+1)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, 0, nil, err
	}
	if len(buf) < 5 {
		return 0, 0, nil, errors.New("payload too short")
	}
	classID = binary.BigEndian.Uint16(buf[0:2])
	methodID = binary.BigEndian.Uint16(buf[2:4])
	return classID, methodID, buf[4:size], nil
}

// amqpConnectionStartPayload builds a minimal Connection.Start payload.
func amqpConnectionStartPayload() []byte {
	// version_major(1) + version_minor(1) + server_properties(table, empty=4) +
	// mechanisms(long-string "PLAIN") + locales(long-string "en_US")
	mechanism := "PLAIN"
	locale := "en_US"
	size := 2 + 4 + 4 + len(mechanism) + 4 + len(locale)
	buf := make([]byte, size)
	buf[0] = 0 // version_major
	buf[1] = 9 // version_minor
	offset := 2
	binary.BigEndian.PutUint32(buf[offset:], 0) // empty server_properties table
	offset += 4
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(mechanism)))
	offset += 4
	copy(buf[offset:], mechanism)
	offset += len(mechanism)
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(locale)))
	offset += 4
	copy(buf[offset:], locale)
	return buf
}

// amqpConnectionTunePayload builds a minimal Connection.Tune payload.
func amqpConnectionTunePayload() []byte {
	// channel_max(2) + frame_max(4) + heartbeat(2)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint16(buf[0:2], 2047)   // channel_max
	binary.BigEndian.PutUint32(buf[2:6], 131072) // frame_max
	binary.BigEndian.PutUint16(buf[6:8], 60)     // heartbeat
	return buf
}

// amqpConnectionClosePayload builds a minimal Connection.Close payload.
func amqpConnectionClosePayload(code uint16, text string) []byte {
	// reply_code(2) + reply_text(short-string) + class_id(2) + method_id(2)
	size := 2 + 1 + len(text) + 4
	buf := make([]byte, size)
	binary.BigEndian.PutUint16(buf[0:2], code)
	buf[2] = byte(len(text))
	copy(buf[3:], text)
	offset := 3 + len(text)
	binary.BigEndian.PutUint16(buf[offset:], 0)   // class_id
	binary.BigEndian.PutUint16(buf[offset+2:], 0) // method_id
	return buf
}

// amqpParseSASLPlain extracts username and password from a Connection.Start-Ok payload.
// The payload format is: client_properties(table) + mechanism(short-string) + response(long-string) + locale(short-string).
// The SASL PLAIN response is: \x00username\x00password.
func amqpParseSASLPlain(payload []byte) (user, pass string, ok bool) {
	if len(payload) < 4 {
		return "", "", false
	}
	// Skip client_properties table.
	tableSize := binary.BigEndian.Uint32(payload[0:4])
	offset := 4 + int(tableSize)
	if offset >= len(payload) {
		return "", "", false
	}
	// Skip mechanism short-string.
	mechLen := int(payload[offset])
	offset += 1 + mechLen
	if offset+4 > len(payload) {
		return "", "", false
	}
	// Read response long-string.
	respLen := binary.BigEndian.Uint32(payload[offset : offset+4])
	offset += 4
	if offset+int(respLen) > len(payload) {
		return "", "", false
	}
	response := string(payload[offset : offset+int(respLen)])
	// SASL PLAIN format: \x00username\x00password
	parts := strings.SplitN(response, "\x00", 3)
	if len(parts) != 3 || parts[0] != "" {
		return "", "", false
	}
	return parts[1], parts[2], true
}
