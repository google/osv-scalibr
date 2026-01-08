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

package validators

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/osv-scalibr/veles"
)

// HTTPValidator validates a URL using Basic or Digest authentication.
type HTTPValidator struct{ Client *http.Client }

// Validate implements the standard challenge-response mechanism.
// It sends an unauthenticated probe first, then attempts authentication
// based on the server's response.
func (h *HTTPValidator) Validate(ctx context.Context, u *url.URL) (veles.ValidationStatus, error) {
	// Strip user info to force a 401 challenge.
	probeURL := *u
	probeURL.User = nil

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
	if err != nil {
		return veles.ValidationFailed, err
	}

	resp, err := h.Client.Do(req)
	if err != nil {
		return veles.ValidationFailed, err
	}
	resp.Body.Close()

	// If the resource is open (200 OK) without credentials, validation is impossible.
	if resp.StatusCode == http.StatusOK {
		return veles.ValidationFailed, fmt.Errorf("resource is public; cannot validate credentials")
	}

	// A 401 status is expected to proceed with validation.
	if resp.StatusCode != http.StatusUnauthorized {
		return veles.ValidationFailed, fmt.Errorf("unexpected status during probe: %s", resp.Status)
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("error building authenticated request: %w", err)
	}
	// Add probe response cookies
	// This was needed when testing against flask_httpauth.HTTPDigestAuth.
	for _, c := range resp.Cookies() {
		req.AddCookie(c)
	}

	// Check the WWW-Authenticate header.
	authHeader := strings.ToLower(resp.Header.Get("WWW-Authenticate"))
	switch {
	case strings.HasPrefix(authHeader, "digest"):
		digest, err := buildDigest(u, authHeader)
		if err != nil {
			return veles.ValidationFailed, err
		}
		req.Header.Set("Authorization", digest)
	default:
		// Use Basic Auth as default
		password, _ := u.User.Password()
		req.SetBasicAuth(u.User.Username(), password)
	}

	resp, err = h.Client.Do(req)
	if err != nil {
		return veles.ValidationFailed, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return veles.ValidationValid, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return veles.ValidationInvalid, nil
	default:
		return veles.ValidationFailed, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

// buildDigest returns a new request with a Digest header
func buildDigest(u *url.URL, challenge string) (string, error) {
	params := parseAuthHeader(challenge)

	// Verify Digest Algorithm (only MD5 is supported).
	if alg := params["algorithm"]; alg != "" && strings.ToUpper(alg) != "MD5" {
		return "", fmt.Errorf("unsupported digest algorithm: %s", alg)
	}

	// Gather parameters.
	var (
		realm       = params["realm"]
		nonce       = params["nonce"]
		qop         = params["qop"]
		opaque      = params["opaque"]
		username    = u.User.Username()
		password, _ = u.User.Password()
		uri         = u.RequestURI()
	)

	clientNonceBytes := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, clientNonceBytes); err != nil {
		return "", fmt.Errorf("failed to generate cnonce: %w", err)
	}
	clientNonce := hex.EncodeToString(clientNonceBytes)
	nonceCount := "00000001"
	ha1 := md5Hash(fmt.Sprintf("%s:%s:%s", username, realm, password))
	ha2 := md5Hash(fmt.Sprintf("%s:%s", http.MethodGet, uri))

	// Calculate Response.
	// Standard: MD5(HA1:nonce:nc:cnonce:qop:HA2).
	// Legacy:   MD5(HA1:nonce:HA2).
	var response string
	if qop == "auth" || qop == "auth-int" {
		response = md5Hash(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, nonce, nonceCount, clientNonce, qop, ha2))
	} else {
		response = md5Hash(fmt.Sprintf("%s:%s:%s", ha1, nonce, ha2))
	}

	headerVal := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		username, realm, nonce, uri, response)
	if opaque != "" {
		headerVal += fmt.Sprintf(`, opaque="%s"`, opaque)
	}
	if qop != "" {
		headerVal += fmt.Sprintf(`, qop=%s, nc=%s, cnonce="%s"`, qop, nonceCount, clientNonce)
	}
	return headerVal, nil
}

func md5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

// parseAuthHeader parses keys and values from the WWW-Authenticate header.
func parseAuthHeader(header string) map[string]string {
	params := make(map[string]string)

	// Skip the scheme (ignore it if not present)
	_, header, _ = strings.Cut(header, " ")

	// Note: commas inside quoted strings are not handled.
	for part := range strings.SplitSeq(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		params[strings.TrimSpace(kv[0])] = strings.Trim(strings.TrimSpace(kv[1]), `"`)
	}

	return params
}
