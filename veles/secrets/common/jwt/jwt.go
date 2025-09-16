// Copyright 2025 Google LLC
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
	// payload is the base64 decoded JWT header claims.
	payload map[string]any
	// signature is the raw signature section of the JWT.
	signature string
}

// Header returns a copy of the JWT header claims.
func (t *Token) Header() map[string]any {
	return copyMap(t.header)
}

// Payload returns a copy of the JWT payload claims.
func (t *Token) Payload() map[string]any {
	return copyMap(t.payload)
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

// copyMap creates a shallow copy of a map[string]any.
// Returns nil if the input map is nil.
func copyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}

	n := make(map[string]any, len(m))
	for k, v := range m {
		n[k] = v
	}

	return n
}

// ExtractTokens scans the input data for JWT substrings, parses them and
// returns a slice of Token objects and their positions.
func ExtractTokens(data []byte) ([]Token, []int) {
	if len(data) > MaxTokenLength {
		return nil, nil
	}

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
