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

package httpauth

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// SetDigestAuth adds the "Authorization" header generating the value from the given UserInfo and server challenge (from the WWW-Authenticate header) (RFC 7616).
func SetDigestAuth(req *http.Request, user *url.Userinfo, serverChallenge string) error {
	nonce := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate cnonce: %w", err)
	}
	return SetDigestAuthWithNonce(req, user, serverChallenge, hex.EncodeToString(nonce))
}

// SetDigestAuthWithNonce adds the "Authorization" header generating the value from the given UserInfo, server challenge and a nonce (from the WWW-Authenticate header) (RFC 7616).
func SetDigestAuthWithNonce(req *http.Request, user *url.Userinfo, serverChallenge string, clientNonce string) error {
	if req.Method != http.MethodGet {
		return fmt.Errorf("method %q not supported", req.Method)
	}

	const prefix = "Digest "
	if !strings.HasPrefix(serverChallenge, prefix) {
		return errors.New("not a digest auth header")
	}
	params := parsePairs(serverChallenge[len(prefix):])
	if params == nil {
		return errors.New("malformed digest header")
	}

	var (
		alg         = params["algorithm"]
		realm       = params["realm"]
		nonce       = params["nonce"]
		qop         = pickQOP(params["qop"])
		opaque      = params["opaque"]
		username    = user.Username()
		password, _ = user.Password()
		uri         = req.URL.RequestURI()
	)

	hashFunc, err := getHashFunc(alg)
	if err != nil {
		return err
	}

	nonceCount := "00000001"
	ha1 := hashFunc(fmt.Sprintf("%s:%s:%s", username, realm, password))
	ha2 := hashFunc(fmt.Sprintf("%s:%s", req.Method, uri))

	// Calculate Response.
	var response string
	if qop != "" {
		// Standard: MD5(HA1:nonce:nc:cnonce:qop:HA2).
		response = hashFunc(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, nonce, nonceCount, clientNonce, qop, ha2))
	} else {
		// Legacy (RFC 2069): MD5(HA1:nonce:HA2)
		response = hashFunc(fmt.Sprintf("%s:%s:%s", ha1, nonce, ha2))
	}

	headerVal := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		username, realm, nonce, uri, response)

	// RFC 7616 requires sending the algorithm if it's not empty
	if alg != "" {
		headerVal += ", algorithm=" + alg
	}
	if opaque != "" {
		headerVal += fmt.Sprintf(`, opaque="%s"`, opaque)
	}
	if qop != "" {
		headerVal += fmt.Sprintf(`, qop=%s, nc=%s, cnonce="%s"`, qop, nonceCount, clientNonce)
	}
	req.Header.Set("Authorization", headerVal)
	return nil
}

// pickQOP parses the comma-separated qop list and returns the first method.
func pickQOP(qopList string) string {
	tokens := strings.Split(qopList, ",")
	if len(tokens) == 0 {
		return qopList
	}
	return tokens[0]
}

// getHashFunc returns an hash function based on the given algorithm name.
func getHashFunc(alg string) (func(string) string, error) {
	alg = strings.ToUpper(alg)

	switch alg {
	case "", "MD5":
		return md5Hash, nil
	case "SHA-256":
		return sha256Hash, nil
	default:
		return nil, fmt.Errorf("unsupported digest algorithm: %s", alg)
	}
}

func md5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func sha256Hash(text string) string {
	hasher := sha256.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}
