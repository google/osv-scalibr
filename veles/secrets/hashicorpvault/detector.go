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

package hashicorpvault

import (
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of a Vault token.
const maxTokenLength = 200

// maxUUIDLength is the maximum size of a UUID (AppRole credential).
const maxUUIDLength = 36

// vaultTokenRe is a regular expression that matches HashiCorp Vault tokens.
// Vault tokens can start with older prefixes (s., b., r.) or newer prefixes (hvs., hvb.) followed by base64-like characters.
var vaultTokenRe = regexp.MustCompile(`(?:hv[sb]|[sbr])\.[A-Za-z0-9_-]{24,}`)

// appRoleCredentialRe is a regular expression that matches UUID v4 format used for AppRole credentials.
// UUIDs have the format: 8-4-4-4-12 hexadecimal digits separated by hyphens.
var appRoleCredentialRe = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// appRoleContextRe matches potential AppRole credential pairs with context labels.
// This matches patterns like "role_id: uuid", "ROLE_ID=uuid", "secret_id: uuid" etc.
var appRoleContextRe = regexp.MustCompile(`(?i)(role_id|secret_id)\s*[:\s=]\s*([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`)

// appRoleDetector implements context-aware AppRole credential detection.
type appRoleDetector struct {
	maxUUIDLen    uint32
	maxContextLen uint32 // Maximum distance to look for context
}

// NewTokenDetector returns a new simpletoken.Detector that matches HashiCorp Vault tokens.
func NewTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     vaultTokenRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return Token{Token: string(b)}, true
		},
	}
}

// NewAppRoleDetector returns a context-aware detector that matches UUID-formatted AppRole credentials.
// This detector analyzes surrounding context to identify role_id and secret_id pairs when possible,
// falling back to individual UUID detection when context is unclear.
func NewAppRoleDetector() veles.Detector {
	return &appRoleDetector{
		maxUUIDLen:    maxUUIDLength,
		maxContextLen: 500, // Look up to 500 bytes around each UUID for context
	}
}

// MaxSecretLen returns the maximum length of secrets this detector can find.
func (d *appRoleDetector) MaxSecretLen() uint32 {
	return d.maxContextLen
}

// Detect implements context-aware AppRole credential detection.
func (d *appRoleDetector) Detect(data []byte) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var positions []int

	// First, try to find context-aware credential pairs
	contextMatches := appRoleContextRe.FindAllSubmatchIndex(data, -1)
	processedUUIDs := make(map[string]bool)

	// Group matches by proximity to find potential pairs
	credentialPairs := groupCredentialsByProximity(data, contextMatches, processedUUIDs)

	for _, pair := range credentialPairs {
		secrets = append(secrets, pair.credentials)
		positions = append(positions, pair.position)
	}

	// Then find standalone UUIDs that weren't part of context matches
	uuidMatches := appRoleCredentialRe.FindAllSubmatchIndex(data, -1)
	for _, match := range uuidMatches {
		start, end := match[0], match[1]
		uuid := string(data[start:end])

		if !processedUUIDs[uuid] {
			secrets = append(secrets, AppRoleCredentials{ID: uuid})
			positions = append(positions, start)
		}
	}

	return secrets, positions
}

// credentialPair represents a detected AppRole credential pair with its position.
type credentialPair struct {
	credentials AppRoleCredentials
	position    int
}

// groupCredentialsByProximity analyzes context matches to group role_id/secret_id pairs.
func groupCredentialsByProximity(data []byte, matches [][]int, processedUUIDs map[string]bool) []credentialPair {
	var pairs []credentialPair

	// Convert matches to a more workable format
	type contextMatch struct {
		fieldType string // "role_id" or "secret_id"
		uuid      string
		position  int
	}

	var contextMatches []contextMatch
	for _, match := range matches {
		if len(match) >= 6 { // Now we have 3 capture groups: full match, field type, UUID
			fieldType := strings.ToLower(string(data[match[2]:match[3]]))
			uuid := string(data[match[4]:match[5]])

			contextMatches = append(contextMatches, contextMatch{
				fieldType: fieldType,
				uuid:      uuid,
				position:  match[0],
			})
			processedUUIDs[uuid] = true
		}
	}

	// Group nearby matches into credential pairs
	for i, match1 := range contextMatches {
		if match1.fieldType == "role_id" {
			// Look for a nearby secret_id
			for j, match2 := range contextMatches {
				if i != j && match2.fieldType == "secret_id" {
					// Check if they're within reasonable proximity (e.g., within 200 bytes)
					distance := abs(match1.position - match2.position)
					if distance < 200 {
						pairs = append(pairs, credentialPair{
							credentials: AppRoleCredentials{
								RoleID:   match1.uuid,
								SecretID: match2.uuid,
							},
							position: minInt(match1.position, match2.position),
						})
						break
					}
				}
			}
		}
	}

	// Add standalone context matches that didn't form pairs
	usedInPairs := make(map[string]bool)
	for _, pair := range pairs {
		usedInPairs[pair.credentials.RoleID] = true
		usedInPairs[pair.credentials.SecretID] = true
	}

	for _, match := range contextMatches {
		if !usedInPairs[match.uuid] {
			var creds AppRoleCredentials
			if match.fieldType == "role_id" {
				creds.RoleID = match.uuid
			} else {
				creds.SecretID = match.uuid
			}
			pairs = append(pairs, credentialPair{
				credentials: creds,
				position:    match.position,
			})
		}
	}

	return pairs
}

// Helper functions
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
