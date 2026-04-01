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

package mongodbatlasapikey

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/osv-scalibr/veles"
)

const atlasAPIURL = "https://cloud.mongodb.com/api/atlas/v2/"

// Validator is a Veles Validator for MongoDB Atlas API key pairs.
// It uses HTTP Digest Authentication (RFC 2617) against the Atlas Admin API.
type Validator struct {
	client *http.Client
}

// NewValidator creates a new Validator.
func NewValidator() *Validator {
	return &Validator{
		client: http.DefaultClient,
	}
}

// SetHTTPClient configures the http.Client that the Validator uses.
func (v *Validator) SetHTTPClient(cli *http.Client) {
	v.client = cli
}

// Validate checks whether the given MongoDB Atlas API key pair is valid
// using HTTP Digest Authentication against the Atlas Admin API v2.
func (v *Validator) Validate(ctx context.Context, key Credentials) (veles.ValidationStatus, error) {
	// Step 1: Send unauthenticated request to get Digest Auth challenge.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, atlasAPIURL, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", "osv-scalibr")
	req.Header.Set("Accept", "application/vnd.atlas.2023-01-01+json")

	resp, err := v.client.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("initial request: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		return veles.ValidationFailed, fmt.Errorf("expected 401 challenge, got %d", resp.StatusCode)
	}

	challenge := resp.Header.Get("Www-Authenticate")
	if challenge == "" {
		return veles.ValidationFailed, errors.New("missing WWW-Authenticate header")
	}

	// Step 2: Parse the Digest challenge and compute response.
	params := parseDigestChallenge(challenge)
	realm := params["realm"]
	nonce := params["nonce"]
	qop := params["qop"]
	if realm == "" || nonce == "" {
		return veles.ValidationFailed, errors.New("incomplete digest challenge")
	}

	authHeader, err := computeDigestAuth(key.PublicKey, key.PrivateKey, "GET", "/api/atlas/v2/", realm, nonce, qop)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("computing digest auth: %w", err)
	}

	// Step 3: Send authenticated request.
	authReq, err := http.NewRequestWithContext(ctx, http.MethodGet, atlasAPIURL, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("building auth request: %w", err)
	}
	authReq.Header.Set("User-Agent", "osv-scalibr")
	authReq.Header.Set("Accept", "application/vnd.atlas.2023-01-01+json")
	authReq.Header.Set("Authorization", authHeader)

	authResp, err := v.client.Do(authReq)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("auth request: %w", err)
	}
	authResp.Body.Close()

	switch authResp.StatusCode {
	case http.StatusOK:
		return veles.ValidationValid, nil
	case http.StatusUnauthorized:
		return veles.ValidationInvalid, nil
	case http.StatusForbidden:
		// Authenticated but lacks permissions — key is valid.
		return veles.ValidationValid, nil
	default:
		return veles.ValidationFailed, fmt.Errorf("unexpected status: %d", authResp.StatusCode)
	}
}

// parseDigestChallenge extracts key-value parameters from a Digest WWW-Authenticate header.
func parseDigestChallenge(header string) map[string]string {
	params := make(map[string]string)
	header = strings.TrimPrefix(header, "Digest ")
	for part := range strings.SplitSeq(header, ",") {
		part = strings.TrimSpace(part)
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		params[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return params
}

// computeDigestAuth computes an HTTP Digest Authentication header value per RFC 2617.
func computeDigestAuth(username, password, method, uri, realm, nonce, qop string) (string, error) {
	ha1 := md5Hex(username + ":" + realm + ":" + password)
	ha2 := md5Hex(method + ":" + uri)

	cnonce, err := generateCNonce()
	if err != nil {
		return "", fmt.Errorf("generating cnonce: %w", err)
	}
	nc := "00000001"

	var response string
	if qop == "auth" || qop == "auth-int" {
		response = md5Hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
	} else {
		response = md5Hex(ha1 + ":" + nonce + ":" + ha2)
	}

	return fmt.Sprintf(
		`Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=%s, nc=%s, cnonce="%s", response="%s"`,
		username, realm, nonce, uri, qop, nc, cnonce, response,
	), nil
}

func md5Hex(s string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(s)))
}

func generateCNonce() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
