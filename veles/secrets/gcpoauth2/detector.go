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

package gcpoauth2

import (
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/veles"
)

// clientIDRe is a regular expression that matches GCP OAuth2 client IDs.
// Pattern: numeric-prefix-alphanumeric.apps.googleusercontent.com
var clientIDRe = regexp.MustCompile(`[0-9]{10,15}-[a-zA-Z0-9_-]+\.apps\.googleusercontent\.com`)

// clientSecretRe is a regular expression that matches potential client secrets.
// GCP OAuth2 client secrets are typically 24+ character alphanumeric strings with some special chars
var clientSecretRe = regexp.MustCompile(`[a-zA-Z0-9_-]{24,}`)

// clientCredentialContextRe matches potential OAuth2 credential pairs with context labels.
// This matches patterns like "client_id": "...", CLIENT_ID=..., client_secret: "..." etc.
var clientCredentialContextRe = regexp.MustCompile(`(?i)"?(?P<fieldtype>client_id|client_secret)"?\s*[:=]\s*"?(?P<value>[^"'\s,}\n]+)"?`)

// clientCredentialsDetector implements context-aware OAuth2 client credentials detection.
type clientCredentialsDetector struct {
	maxContextLen uint32 // Maximum distance to look for context
}

// NewDetector returns a context-aware detector that matches GCP OAuth2 client credentials.
// This detector analyzes surrounding context to identify client_id and client_secret pairs when possible,
// falling back to individual credential detection when context is unclear.
func NewDetector() veles.Detector {
	return &clientCredentialsDetector{
		maxContextLen: 1000, // Look up to 1000 bytes around each credential for context
	}
}

// MaxSecretLen returns the maximum length of secrets this detector can find.
func (d *clientCredentialsDetector) MaxSecretLen() uint32 {
	return d.maxContextLen
}

// Detect implements context-aware OAuth2 client credentials detection.
func (d *clientCredentialsDetector) Detect(data []byte) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var positions []int

	// First, try to find context-aware credential pairs
	contextMatches := clientCredentialContextRe.FindAllSubmatchIndex(data, -1)
	processedCredentials := make(map[string]bool)

	// Group matches by proximity to find potential pairs
	credentialPairs := groupCredentialsByProximity(data, contextMatches, processedCredentials)

	for _, pair := range credentialPairs {
		secrets = append(secrets, pair.credentials)
		positions = append(positions, pair.position)
	}

	// Then find standalone client IDs that weren't part of context matches
	clientIDMatches := clientIDRe.FindAllSubmatchIndex(data, -1)
	for _, match := range clientIDMatches {
		start, end := match[0], match[1]
		clientID := string(data[start:end])

		if !processedCredentials[clientID] {
			secrets = append(secrets, ClientCredentials{ID: clientID})
			positions = append(positions, start)
		}
	}

	return secrets, positions
}

// credentialPair represents a detected OAuth2 credential pair with its position.
type credentialPair struct {
	credentials ClientCredentials
	position    int
}

// groupCredentialsByProximity analyzes context matches to group client_id/client_secret pairs.
func groupCredentialsByProximity(data []byte, matches [][]int, processedCredentials map[string]bool) []credentialPair {
	var pairs []credentialPair

	// Convert matches to a more workable format
	type contextMatch struct {
		fieldType string // "client_id" or "client_secret"
		value     string
		position  int
	}

	var contextMatches []contextMatch
	fieldTypeIndex := clientCredentialContextRe.SubexpIndex("fieldtype")
	valueIndex := clientCredentialContextRe.SubexpIndex("value")

	for _, match := range matches {
		if len(match) > fieldTypeIndex && len(match) > valueIndex {
			fieldType := strings.ToLower(string(data[match[fieldTypeIndex*2]:match[fieldTypeIndex*2+1]]))
			value := string(data[match[valueIndex*2]:match[valueIndex*2+1]])

			// Validate client ID format if this is a client_id field
			if fieldType == "client_id" {
				if !clientIDRe.MatchString(value) {
					continue // Skip invalid client IDs
				}
			}

			// Validate client secret format if this is a client_secret field
			if fieldType == "client_secret" {
				if !clientSecretRe.MatchString(value) {
					continue // Skip invalid client secrets
				}
			}

			contextMatches = append(contextMatches, contextMatch{
				fieldType: fieldType,
				value:     value,
				position:  match[0],
			})
			processedCredentials[value] = true
		}
	}

	// Group nearby matches into credential pairs
	usedClientIDs := make(map[string]bool)
	usedClientSecrets := make(map[string]bool)

	for i, match1 := range contextMatches {
		if match1.fieldType == "client_id" && !usedClientIDs[match1.value] {
			// Look for the closest client_secret within allowed distance
			var closestSecret *contextMatch
			maxAllowedDistance := 400             // Maximum allowed distance
			minDistance := maxAllowedDistance + 1 // Track smallest distance found

			for j, match2 := range contextMatches {
				if i != j && match2.fieldType == "client_secret" && !usedClientSecrets[match2.value] {
					distance := abs(match1.position - match2.position)
					if distance <= maxAllowedDistance && distance < minDistance {
						minDistance = distance
						closestSecret = &contextMatches[j]
					}
				}
			}

			if closestSecret != nil {
				pairs = append(pairs, credentialPair{
					credentials: ClientCredentials{
						ClientID:     match1.value,
						ClientSecret: closestSecret.value,
					},
					position: minInt(match1.position, closestSecret.position),
				})
				usedClientIDs[match1.value] = true
				usedClientSecrets[closestSecret.value] = true
			}
		}
	}

	// Add standalone context matches that didn't form pairs
	for _, match := range contextMatches {
		if match.fieldType == "client_id" && !usedClientIDs[match.value] {
			pairs = append(pairs, credentialPair{
				credentials: ClientCredentials{ClientID: match.value},
				position:    match.position,
			})
		} else if match.fieldType == "client_secret" && !usedClientSecrets[match.value] {
			pairs = append(pairs, credentialPair{
				credentials: ClientCredentials{ClientSecret: match.value},
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
