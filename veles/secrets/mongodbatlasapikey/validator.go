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
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/veles"
)

const (
	// atlasEndpoint is the MongoDB Atlas Admin API v2 endpoint used for validation.
	atlasEndpoint = "https://cloud.mongodb.com/api/atlas/v2"
)

// Validator validates MongoDB Atlas API keys via the Atlas Admin API
// using HTTP Digest Authentication.
type Validator struct {
	// Endpoint overrides the default Atlas API endpoint (for testing).
	Endpoint string
	// HTTPC is the HTTP client to use. Uses http.DefaultClient if nil.
	HTTPC *http.Client
}

// NewValidator creates a new Validator for MongoDB Atlas API keys.
func NewValidator() *Validator {
	return &Validator{}
}

// Validate validates a MongoDB Atlas API key pair by performing HTTP Digest
// Authentication against the Atlas Admin API v2.
//
// A GET request is sent to the API root endpoint. If the server responds with
// HTTP 200, the key is valid. If 401 after digest auth, the key is invalid.
func (v *Validator) Validate(ctx context.Context, secret APIKey) (veles.ValidationStatus, error) {
	if secret.PublicKey == "" || secret.PrivateKey == "" {
		return veles.ValidationInvalid, nil
	}

	client := v.HTTPC
	if client == nil {
		client = http.DefaultClient
	}

	endpoint := v.Endpoint
	if endpoint == "" {
		endpoint = atlasEndpoint
	}

	// Step 1: Send initial request without authentication to get the WWW-Authenticate challenge.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("creating initial request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return veles.ValidationFailed, ctx.Err()
		}
		return veles.ValidationFailed, fmt.Errorf("initial request failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		// Unexpected response to unauthenticated request.
		return veles.ValidationFailed, fmt.Errorf("unexpected status %d on initial request", resp.StatusCode)
	}

	wwwAuth := resp.Header.Get("Www-Authenticate")
	if wwwAuth == "" {
		return veles.ValidationFailed, errors.New("missing Www-Authenticate header")
	}

	challenge, err := parseDigestChallenge(wwwAuth)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("parsing digest challenge: %w", err)
	}

	// Step 2: Compute digest response and send authenticated request.
	authHeader := computeDigestAuth(secret.PublicKey, secret.PrivateKey, "GET", endpoint, challenge)

	authReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("creating auth request: %w", err)
	}
	authReq.Header.Set("Authorization", authHeader)

	authResp, err := client.Do(authReq)
	if err != nil {
		if ctx.Err() != nil {
			return veles.ValidationFailed, ctx.Err()
		}
		return veles.ValidationFailed, fmt.Errorf("auth request failed: %w", err)
	}
	authResp.Body.Close()

	switch authResp.StatusCode {
	case http.StatusOK:
		return veles.ValidationValid, nil
	case http.StatusForbidden:
		// 403 means the key is valid but lacks permissions for this endpoint.
		return veles.ValidationValid, nil
	case http.StatusUnauthorized:
		return veles.ValidationInvalid, nil
	default:
		return veles.ValidationFailed, fmt.Errorf("unexpected status %d", authResp.StatusCode)
	}
}

// digestChallenge holds parsed fields from a Www-Authenticate: Digest header.
type digestChallenge struct {
	realm     string
	nonce     string
	qop       string
	algorithm string
}

var digestFieldRe = regexp.MustCompile(`(\w+)="([^"]*)"`)

// parseDigestChallenge parses a Www-Authenticate: Digest header value.
func parseDigestChallenge(header string) (*digestChallenge, error) {
	if !strings.HasPrefix(header, "Digest ") {
		return nil, fmt.Errorf("not a Digest challenge: %s", header)
	}

	c := &digestChallenge{algorithm: "MD5"}
	matches := digestFieldRe.FindAllStringSubmatch(header, -1)
	for _, m := range matches {
		switch strings.ToLower(m[1]) {
		case "realm":
			c.realm = m[2]
		case "nonce":
			c.nonce = m[2]
		case "qop":
			c.qop = m[2]
		case "algorithm":
			c.algorithm = m[2]
		}
	}

	if c.nonce == "" {
		return nil, errors.New("missing nonce in digest challenge")
	}

	return c, nil
}

// computeDigestAuth computes the Authorization header for HTTP Digest Authentication
// (RFC 2617). MD5 is mandated by the protocol — MongoDB Atlas Admin API v1.0 requires it.
// This mirrors clients/datasource/http_auth.go which uses the same pattern.
func computeDigestAuth(username, password, method, uri string, c *digestChallenge) string {
	//nolint:gosec // MD5 is required by HTTP Digest Auth (RFC 2617), not used for password storage.
	ha1 := fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", username, c.realm, password))))
	//nolint:gosec // MD5 is required by HTTP Digest Auth (RFC 2617).
	ha2 := fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s", method, uri))))

	nc := "00000001"
	cnonce := fmt.Sprintf("%08x", rand.Int31())

	var response string
	if strings.Contains(c.qop, "auth") {
		//nolint:gosec // MD5 is required by HTTP Digest Auth (RFC 2617).
		response = fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, c.nonce, nc, cnonce, "auth", ha2))))
	} else {
		//nolint:gosec // MD5 is required by HTTP Digest Auth (RFC 2617).
		response = fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", ha1, c.nonce, ha2))))
	}

	parts := []string{
		fmt.Sprintf(`username="%s"`, username),
		fmt.Sprintf(`realm="%s"`, c.realm),
		fmt.Sprintf(`nonce="%s"`, c.nonce),
		fmt.Sprintf(`uri="%s"`, uri),
		fmt.Sprintf(`response="%s"`, response),
		"algorithm=" + c.algorithm,
	}

	if strings.Contains(c.qop, "auth") {
		parts = append(parts,
			"qop=auth",
			"nc="+nc,
			fmt.Sprintf(`cnonce="%s"`, cnonce),
		)
	}

	return "Digest " + strings.Join(parts, ", ")
}
