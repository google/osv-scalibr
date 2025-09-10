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
	"strings"
)

// ExtractClaimsPayload returns the claims from the payload section of a JWT token
func ExtractClaimsPayload(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}

	// Decode the payload (second part)
	payload, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}

	// Unmarshal the claims
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}

	return claims
}
