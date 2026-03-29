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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	"go.mongodb.org/mongo-driver/v2/bson"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh"
)

func TestValidator(t *testing.T) {
	basicAuthHTTPSvr := mockBasicAuthHTTPServer(t, "admin", "pass")
	digestHTTPSvr := mockDigestHTTPServer(t, "admin", "pass", false)
	digestHTTPSvrWithCookies := mockDigestHTTPServer(t, "admin", "pass", true)
	ftpAddr := mockFTPServer(t, "user", "pass")
	sftpAddr := mockSSHServer(t, "sshuser", "sshpass")
	mongoAddr := mockMongoDBServer(t, "mongouser", "mongopass")

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
		// MongoDB Tests
		{
			name: "mongodb_valid",
			url:  fmt.Sprintf("mongodb://mongouser:mongopass@%s/testdb", mongoAddr),
			want: veles.ValidationValid,
		},
		{
			name: "mongodb_invalid",
			url:  fmt.Sprintf("mongodb://mongouser:wrong@%s/testdb", mongoAddr),
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

// --- MongoDB mock server ---

// mongoWireMsg holds a parsed MongoDB wire protocol message.
type mongoWireMsg struct {
	doc    []byte
	reqID  int32
	opCode uint32
}

func mockMongoDBServer(t *testing.T, validUser, validPass string) string {
	t.Helper()

	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go handleMongoConn(conn, validUser, validPass, salt)
		}
	}()

	return l.Addr().String()
}

func handleMongoConn(conn net.Conn, validUser, validPass string, salt []byte) {
	defer conn.Close()

	const scramIterations = 4096
	var clientFirstBare, serverFirstMsg, serverNonce string
	authDone := false

	for {
		msg, err := readMongoMsg(conn)
		if err != nil {
			return
		}

		var cmd bson.D
		if err := bson.Unmarshal(msg.doc, &cmd); err != nil {
			return
		}
		if len(cmd) == 0 {
			return
		}

		var resp []byte

		switch cmd[0].Key {
		case "hello", "ismaster", "isMaster":
			resp, _ = bson.Marshal(bson.D{
				{Key: "ok", Value: 1.0},
				{Key: "helloOk", Value: true},
				{Key: "isWritablePrimary", Value: true},
				{Key: "maxWireVersion", Value: int32(21)},
				{Key: "minWireVersion", Value: int32(0)},
				{Key: "maxBsonObjectSize", Value: int32(16777216)},
				{Key: "maxMessageSizeBytes", Value: int32(48000000)},
				{Key: "maxWriteBatchSize", Value: int32(100000)},
				{Key: "connectionId", Value: int32(1)},
				{Key: "saslSupportedMechs", Value: bson.A{"SCRAM-SHA-256"}},
			})

		case "saslStart":
			payload := getMongoPayload(cmd)
			clientFirst := string(payload)
			clientFirstBare = strings.TrimPrefix(clientFirst, "n,,")
			parts := parseSCRAMKV(clientFirstBare)
			clientNonce := parts["r"]
			serverNonce = clientNonce + "srv" + base64.StdEncoding.EncodeToString(salt[:8])

			serverFirstMsg = fmt.Sprintf("r=%s,s=%s,i=%d",
				serverNonce,
				base64.StdEncoding.EncodeToString(salt),
				scramIterations,
			)

			resp, _ = bson.Marshal(bson.D{
				{Key: "conversationId", Value: int32(1)},
				{Key: "payload", Value: bson.Binary{Data: []byte(serverFirstMsg)}},
				{Key: "done", Value: false},
				{Key: "ok", Value: 1.0},
			})

		case "saslContinue":
			if authDone {
				resp, _ = bson.Marshal(bson.D{
					{Key: "conversationId", Value: int32(1)},
					{Key: "payload", Value: bson.Binary{}},
					{Key: "done", Value: true},
					{Key: "ok", Value: 1.0},
				})
				if err := writeMongoResp(conn, msg, resp); err != nil {
					return
				}
				continue
			}

			payload := getMongoPayload(cmd)
			clientFinal := string(payload)
			cfParts := parseSCRAMKV(clientFinal)
			proofB64 := cfParts["p"]
			proof, _ := base64.StdEncoding.DecodeString(proofB64)

			clientFinalNoProof := fmt.Sprintf("c=biws,r=%s", serverNonce)
			authMessage := clientFirstBare + "," + serverFirstMsg + "," + clientFinalNoProof

			saltedPass := pbkdf2.Key([]byte(validPass), salt, scramIterations, 32, sha256.New)
			clientKey := computeHMAC(saltedPass, []byte("Client Key"))
			storedKey := computeHash(clientKey)
			clientSig := computeHMAC(storedKey, []byte(authMessage))
			expectedProof := xorSlices(clientKey, clientSig)

			userParts := parseSCRAMKV(clientFirstBare)
			if userParts["n"] != validUser || !hmac.Equal(proof, expectedProof) {
				resp, _ = bson.Marshal(bson.D{
					{Key: "ok", Value: 0.0},
					{Key: "code", Value: int32(18)},
					{Key: "codeName", Value: "AuthenticationFailed"},
					{Key: "errmsg", Value: "Authentication failed."},
				})
				_ = writeMongoResp(conn, msg, resp)
				return
			}

			serverKey := computeHMAC(saltedPass, []byte("Server Key"))
			serverSig := computeHMAC(serverKey, []byte(authMessage))
			serverFinal := "v=" + base64.StdEncoding.EncodeToString(serverSig)

			authDone = true
			resp, _ = bson.Marshal(bson.D{
				{Key: "conversationId", Value: int32(1)},
				{Key: "payload", Value: bson.Binary{Data: []byte(serverFinal)}},
				{Key: "done", Value: false},
				{Key: "ok", Value: 1.0},
			})

		default:
			resp, _ = bson.Marshal(bson.D{{Key: "ok", Value: 1.0}})
		}

		if err := writeMongoResp(conn, msg, resp); err != nil {
			return
		}
	}
}

// readMongoMsg reads a MongoDB wire protocol message (supports OP_QUERY and OP_MSG).
func readMongoMsg(r io.Reader) (mongoWireMsg, error) {
	header := make([]byte, 16)
	if _, err := io.ReadFull(r, header); err != nil {
		return mongoWireMsg{}, err
	}

	msgLen := binary.LittleEndian.Uint32(header[0:4])
	requestID := int32(binary.LittleEndian.Uint32(header[4:8]))
	opCode := binary.LittleEndian.Uint32(header[12:16])

	body := make([]byte, msgLen-16)
	if _, err := io.ReadFull(r, body); err != nil {
		return mongoWireMsg{}, err
	}

	var doc []byte
	switch opCode {
	case 2013: // OP_MSG
		flagBits := binary.LittleEndian.Uint32(body[0:4])
		end := len(body)
		if flagBits&1 != 0 {
			end -= 4 // strip CRC32C checksum
		}
		doc = body[5:end] // skip flagBits(4) + kind(1)

	case 2004: // OP_QUERY
		// Skip: flags(4) + collectionName(cstring) + numberToSkip(4) + numberToReturn(4)
		pos := 4
		for pos < len(body) && body[pos] != 0 {
			pos++
		}
		pos++ // null terminator
		pos += 8 // numberToSkip + numberToReturn
		doc = body[pos:]

	default:
		return mongoWireMsg{}, fmt.Errorf("unsupported opcode %d", opCode)
	}

	return mongoWireMsg{doc: doc, reqID: requestID, opCode: opCode}, nil
}

// writeMongoResp sends a response using the appropriate wire protocol format.
func writeMongoResp(w io.Writer, req mongoWireMsg, doc []byte) error {
	switch req.opCode {
	case 2004: // OP_QUERY → respond with OP_REPLY (opcode 1)
		// responseFlags(4) + cursorID(8) + startingFrom(4) + numberReturned(4) = 20 bytes
		bodyLen := 20 + len(doc)
		msgLen := uint32(16 + bodyLen)
		buf := make([]byte, 36) // 16 header + 20 reply prefix
		binary.LittleEndian.PutUint32(buf[0:4], msgLen)
		binary.LittleEndian.PutUint32(buf[8:12], uint32(req.reqID))
		binary.LittleEndian.PutUint32(buf[12:16], 1) // OP_REPLY
		// responseFlags, cursorID, startingFrom = 0
		binary.LittleEndian.PutUint32(buf[32:36], 1) // numberReturned
		if _, err := w.Write(buf); err != nil {
			return err
		}
		_, err := w.Write(doc)
		return err

	default: // OP_MSG → respond with OP_MSG
		bodyLen := 4 + 1 + len(doc) // flagBits + kind + doc
		msgLen := uint32(16 + bodyLen)
		buf := make([]byte, 21) // 16 header + 5 (flagBits + kind)
		binary.LittleEndian.PutUint32(buf[0:4], msgLen)
		binary.LittleEndian.PutUint32(buf[8:12], uint32(req.reqID))
		binary.LittleEndian.PutUint32(buf[12:16], 2013) // OP_MSG
		if _, err := w.Write(buf); err != nil {
			return err
		}
		_, err := w.Write(doc)
		return err
	}
}

func getMongoPayload(cmd bson.D) []byte {
	for _, elem := range cmd {
		if elem.Key == "payload" {
			if b, ok := elem.Value.(bson.Binary); ok {
				return b.Data
			}
		}
	}
	return nil
}

func computeHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func computeHash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func xorSlices(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func parseSCRAMKV(s string) map[string]string {
	m := make(map[string]string)
	for _, field := range strings.Split(s, ",") {
		if i := strings.IndexByte(field, '='); i >= 0 {
			m[field[:i]] = field[i+1:]
		}
	}
	return m
}
