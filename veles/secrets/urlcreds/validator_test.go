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
	"context"
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
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/doyensec/safeurl"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/urlcreds"
	"github.com/google/osv-scalibr/veles/velestest"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/dns/dnsmessage"
)

func TestAcceptValidator(t *testing.T) {
	velestest.AcceptValidator(
		t,
		urlcreds.NewValidator(),
		velestest.WithMalformedSecrets(urlcreds.Credentials{FullURL: ":::not-a-valid-url"}),
		velestest.WithTrueNegatives(urlcreds.Credentials{FullURL: "http://admin:pass@domain.com/resource"}),
		velestest.WithBrokenTransport(func(v *urlcreds.Validator) { v.Client = velestest.BrokenClient }),
		velestest.WithoutOnline[urlcreds.Credentials](),
	)
}

func TestValidator(t *testing.T) {
	basicAuthHTTPSvr := mockBasicAuthHTTPServer(t, "admin", "pass")
	digestHTTPSvr := mockDigestHTTPServer(t, "admin", "pass", false)
	digestHTTPSvrWithCookies := mockDigestHTTPServer(t, "admin", "pass", true)
	ftpAddr := mockFTPServer(t, "user", "pass")
	sftpAddr := mockSSHServer(t, "sshuser", "sshpass")

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
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			v := newLocalValidator(t,
				basicAuthHTTPSvr.Listener.Addr().(*net.TCPAddr).Port,
				digestHTTPSvr.Listener.Addr().(*net.TCPAddr).Port,
				digestHTTPSvrWithCookies.Listener.Addr().(*net.TCPAddr).Port,
				addressPort(t, ftpAddr), addressPort(t, sftpAddr))
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

func TestValidatorFTPRejectsLineBreaks(t *testing.T) {
	cases := []struct {
		name string
		user string
		pass string
	}{
		{name: "username_cr", user: "sensitive%0DNOOP", pass: "sensitive"},
		{name: "username_lf", user: "sensitive%0ANOOP", pass: "sensitive"},
		{name: "username_crlf", user: "sensitive%0D%0ANOOP", pass: "sensitive"},
		{name: "password_cr", user: "sensitive", pass: "sensitive%0DNOOP"},
		{name: "password_lf", user: "sensitive", pass: "sensitive%0ANOOP"},
		{name: "password_crlf", user: "sensitive", pass: "sensitive%0D%0ANOOP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { l.Close() })
			connected := make(chan bool, 1)
			go func() {
				conn, err := l.Accept()
				if err != nil {
					connected <- false
					return
				}
				conn.Close()
				connected <- true
			}()

			v := newLocalValidator(t, l.Addr().(*net.TCPAddr).Port)
			got, err := v.Validate(t.Context(), urlcreds.Credentials{
				FullURL: fmt.Sprintf("ftp://%s:%s@%s/files", tc.user, tc.pass, l.Addr()),
			})
			l.Close()
			if <-connected {
				t.Error("Validate() connected despite line breaks in credentials")
			}
			if got != veles.ValidationFailed {
				t.Errorf("Validate() status = %v, want %v", got, veles.ValidationFailed)
			}
			if err == nil {
				t.Error("Validate() returned no error for line breaks in credentials")
			} else if strings.Contains(err.Error(), "sensitive") {
				t.Error("Validate() error exposed credentials")
			}
		})
	}
}

func TestValidatorFTPEncodedCredentials(t *testing.T) {
	addr := mockFTPServer(t, "user@name", "pass:%word")
	u := &url.URL{
		Scheme: "ftp",
		Host:   addr,
		User:   url.UserPassword("user@name", "pass:%word"),
	}
	v := newLocalValidator(t, addressPort(t, addr))
	got, err := v.Validate(t.Context(), urlcreds.Credentials{FullURL: u.String()})
	if err != nil {
		t.Fatalf("Validate(): %v", err)
	}
	if got != veles.ValidationValid {
		t.Errorf("Validate() status = %v, want %v", got, veles.ValidationValid)
	}
}

func TestValidatorBlocksInternalDestinations(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("protected client must not send requests through an environment proxy")
	}))
	t.Cleanup(proxy.Close)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	for _, scheme := range []string{"http", "https", "ftp", "sftp"} {
		t.Run(scheme, func(t *testing.T) {
			for _, host := range []string{
				"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.100.100.200",
				"::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1",
			} {
				v := urlcreds.NewValidator()
				status, err := v.Validate(t.Context(), urlcreds.Credentials{
					FullURL: scheme + "://user:pass@" + net.JoinHostPort(host, "12345") + "/resource",
				})
				if err == nil || status != veles.ValidationFailed {
					t.Fatalf("Validate(%q) = %v, %v; want ValidationFailed and error", host, status, err)
				}
				var blocked *safeurl.AllowedIPError
				if !errors.As(err, &blocked) {
					t.Fatalf("Validate(%q) error = %v; want safeurl destination rejection", host, err)
				}
			}
		})
	}
}

func TestValidatorBlocksRedirectToInternalDestination(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		name := "probe"
		if authenticated {
			name = "authenticated"
		}
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if authenticated && r.Header.Get("Authorization") == "" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
			}))
			t.Cleanup(server.Close)
			// Permit only the local fixture. Redirects must still use the
			// protected transport rather than http.DefaultClient.
			client := safeurl.Client(safeurl.GetConfigBuilder().
				SetAllowedIPs("127.0.0.1").
				SetAllowedPorts(server.Listener.Addr().(*net.TCPAddr).Port, 80).
				SetTimeout(time.Second).
				Build()).Client
			t.Cleanup(client.CloseIdleConnections)
			v := urlcreds.NewValidator().(*urlcreds.Validator)
			v.Client = client
			status, err := v.Validate(t.Context(), urlcreds.Credentials{
				FullURL: strings.Replace(server.URL, "://", "://user:pass@", 1),
			})
			var blocked *safeurl.AllowedIPError
			if status != veles.ValidationFailed || !errors.As(err, &blocked) {
				t.Fatalf("Validate() = %v, %v; want blocked redirect", status, err)
			}
		})
	}
}

func TestValidatorBlocksSpecialUseAddresses(t *testing.T) {
	for _, address := range []string{
		"0.0.0.0", "0.1.2.3", "10.0.0.1", "127.0.0.1", "169.254.169.254",
		"172.16.0.1", "192.168.0.1", "100.100.100.200", "192.0.0.1",
		"192.0.2.1", "192.88.99.1", "198.18.0.1", "198.51.100.1",
		"203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
		"::", "::1", "fc00::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1",
		"::ffff:10.0.0.1", "64:ff9b::a00:1", "64:ff9b:1::1", "100::1",
		"100:0:0:1::1", "2001::1", "2001:db8::1", "2002:7f00:1::1",
		"3fff::1", "5f00::1",
	} {
		status, err := urlcreds.NewValidator().Validate(t.Context(), urlcreds.Credentials{
			FullURL: "ftp://user:pass@" + net.JoinHostPort(address, "22"),
		})
		var blocked *safeurl.AllowedIPError
		if status != veles.ValidationFailed || !errors.As(err, &blocked) {
			t.Errorf("Validate(%q) = %v, %v; want safeurl destination rejection", address, status, err)
		}
	}
}

func TestValidatorChecksReboundAddress(t *testing.T) {
	// An earlier lookup returns a public address. The actual dial resolves the
	// same name to loopback, which must be rejected before opening a connection.
	server, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	var queries atomic.Int32
	go serveRebindingDNS(t, server, &queries)
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", server.LocalAddr().String())
		},
	}
	oldResolver := net.DefaultResolver
	net.DefaultResolver = resolver
	t.Cleanup(func() { net.DefaultResolver = oldResolver })
	for _, scheme := range []string{"ftp", "sftp"} {
		t.Run(scheme, func(t *testing.T) {
			queries.Store(0)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			ips, err := resolver.LookupNetIP(ctx, "ip4", "rebind.example")
			if err != nil || len(ips) != 1 || ips[0].String() != "8.8.8.8" {
				t.Fatalf("initial lookup = %v, %v; want public address", ips, err)
			}
			status, err := urlcreds.NewValidator().Validate(ctx, urlcreds.Credentials{
				FullURL: scheme + "://user:pass@rebind.example:22",
			})
			var blocked *safeurl.AllowedIPError
			if status != veles.ValidationFailed || !errors.As(err, &blocked) {
				t.Fatalf("Validate() = %v, %v; want rejection of rebound address", status, err)
			}
			if queries.Load() < 2 {
				t.Errorf("DNS queries = %d, want at least two", queries.Load())
			}
		})
	}
}

func serveRebindingDNS(t *testing.T, server net.PacketConn, queries *atomic.Int32) {
	t.Helper()
	buf := make([]byte, 512)
	for {
		n, addr, err := server.ReadFrom(buf)
		if err != nil {
			return // Closed by test cleanup.
		}
		var request dnsmessage.Message
		if err := request.Unpack(buf[:n]); err != nil {
			t.Error(err)
			return
		}
		response := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID: request.ID, Response: true, RecursionAvailable: true,
			},
			Questions: request.Questions,
		}
		for _, question := range request.Questions {
			if question.Type != dnsmessage.TypeA {
				continue
			}
			ip := [4]byte{127, 0, 0, 1}
			if queries.Add(1) == 1 {
				ip = [4]byte{8, 8, 8, 8}
			}
			response.Answers = append(response.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
				},
				Body: &dnsmessage.AResource{A: ip},
			})
		}
		data, err := response.Pack()
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := server.WriteTo(data, addr); err != nil {
			t.Error(err)
			return
		}
	}
}

// newLocalValidator permits only the loopback fixtures and their specific ports.
// Production defaults are covered separately by destination-policy tests.
func newLocalValidator(t *testing.T, ports ...int) *urlcreds.Validator {
	t.Helper()
	v := urlcreds.NewValidator().(*urlcreds.Validator)
	v.Client = safeurl.Client(safeurl.GetConfigBuilder().
		SetAllowedIPs("127.0.0.1").
		SetAllowedPorts(ports...).
		SetTimeout(time.Second).
		Build()).Client
	t.Cleanup(v.Client.CloseIdleConnections)
	v.DialContext = v.Client.Transport.(*http.Transport).DialContext
	return v
}

func addressPort(t *testing.T, address string) int {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return n
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
