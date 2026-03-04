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

// Package jwt provides utilities for parsing JSON Web Tokens (JWT).
package jwt

import (
	"encoding/base64"
	"encoding/json"
	"maps"
	"regexp"
	"strings"
)

// MaxTokenLength defines the maximum allowed size of a JWT token.
//
// The JWT specification (RFC 7519) does not define an upper bound for token
// length. However, in practice JWTs are typically transmitted in HTTP headers,
// where very large values can cause interoperability issues. Exceeding 8 KB is
// generally discouraged, as many servers, proxies, and libraries impose limits
// around this size.
const MaxTokenLength = 8192

// jwtRe is a regular expression that matches the basic JWT structure (base64.base64.base64)
var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

// Token represents a decoded JSON Web Token (JWT).
// The JWT consists of three sections: header, payload, and signature.
type Token struct {
	// raw is the original JWT string
	raw string
	// header is the base64 decoded JWT header claims.
	header map[string]any
	// payload is the base64 decoded JWT payload claims.
	payload map[string]any
	// signature is the raw signature section of the JWT.
	signature string
}

// Header returns a copy of the JWT header claims.
func (t *Token) Header() map[string]any {
	return maps.Clone(t.header)
}

// Payload returns a copy of the JWT payload claims.
func (t *Token) Payload() map[string]any {
	return maps.Clone(t.payload)
}

// Signature returns the JWT signature.
func (t *Token) Signature() string {
	return t.signature
}

// Raw returns the JWT string.
func (t *Token) Raw() string {
	return t.raw
}

func (t Token) isValid() bool {
	return t.header != nil && t.payload != nil && t.signature != ""
}

// ExtractTokens scans the input data for JWT substrings, parses them and
// returns a slice of Token objects and their positions.
func ExtractTokens(data []byte) ([]Token, []int) {
	var tokens []Token
	var positions []int
	jwtMatches := jwtRe.FindAllIndex(data, -1)
	for _, m := range jwtMatches {
		token := parseToken(string(data[m[0]:m[1]]))
		if !token.isValid() {
			continue
		}
		tokens = append(tokens, token)
		positions = append(positions, m[0])
	}
	return tokens, positions
}

// ExtractTokensWithContext scans input data using a context-aware regexp.
//
// The provided regexp should contain at least one capturing group where the
// first group represents the JWT value. The returned Token is parsed from
// that first capturing group, while the returned position corresponds to the
// start of the full regex match (including surrounding context).
//
// Example regexp:
//
//	(?i)\baccess[_-]?token\b\s*[:=]?\s*(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b
//
// For input:
//
//	access_token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
//
// The returned position will point to the beginning of "access_token",
// while the parsed token will be extracted only from the captured JWT.
func ExtractTokensWithContext(data []byte, r *regexp.Regexp) ([]Token, []int) {
	var tokens []Token
	var positions []int

	matches := r.FindAllSubmatchIndex(data, -1)

	// idx layout:
	// [fullStart, fullEnd, g1Start, g1End, g2Start, g2End, ...]
	for _, idx := range matches {
		// Ensure first capturing group exists and matched
		if len(idx) < 4 || idx[2] < 0 || idx[3] < 0 {
			continue
		}

		// Extract JWT from first capturing group
		jwtBytes := data[idx[2]:idx[3]]
		if len(jwtBytes) > MaxTokenLength {
			continue
		}

		token := parseToken(string(jwtBytes))
		if !token.isValid() {
			continue
		}

		tokens = append(tokens, token)
		positions = append(positions, idx[0]) // full context span start
	}

	return tokens, positions
}

// parseToken splits and decode a JWT string into a Token.
func parseToken(token string) Token {
	sections := strings.Split(token, ".")
	if len(sections) != 3 {
		return Token{}
	}

	return Token{
		header:    extractClaims(sections[0]),
		payload:   extractClaims(sections[1]),
		signature: sections[2],
		raw:       token,
	}
}

// extractClaims base64 decodes a JWT section and unmarshals it as JSON.
func extractClaims(section string) map[string]any {
	data, err := base64.RawURLEncoding.DecodeString(section)
	if err != nil {
		return nil
	}

	var claims map[string]any
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil
	}
	return claims
}
