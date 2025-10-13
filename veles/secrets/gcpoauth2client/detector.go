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

package gcpoauth2client

import (
	"regexp"
	"slices"

	"github.com/google/osv-scalibr/veles"
)

// Enforce detector interface.
var _ veles.Detector = (*detector)(nil)

const (
	// maxIDLength is the maximum length of a valid client ID.
	// There is not documented length, but examples are ~75 characters.
	// 200 is a good upper bound.
	maxIDLength = 200

	// maxSecretLength is the maximum length of a valid client secret.
	// There is not documented length, but examples are ~35 characters.
	// 100 is a good upper bound.
	maxSecretLength = 100

	// maxDistance is the maximum distance between client IDs and secrets to be considered for pairing.
	// 10 KiB is a good upper bound as we don't expect files containing credentials to be larger than this.
	maxDistance = 10 * 1 << 10 // 10 KiB

	// maxSecretLen is the maximum length of secrets this detector can find.
	// Veles uses this to set the chunk size. Client ID and secrets should be contained within this chunk.
	maxSecretLen = maxIDLength + maxSecretLength + maxDistance
)

var (
	// clientIDRe is a regular expression that matches GCP OAuth2 client IDs.
	// There is no official documentation on the exact format of GCP OAuth2 client IDs.
	// But official docs include examples that end with .apps.googleusercontent.com:
	// - https://developers.google.com/identity/protocols/oauth2/web-server
	//
	// Other references also suggest similar formats:
	// - https://gofastmcp.com/integrations/google
	// - https://web.archive.org/web/20250418010928/https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/google_oauth2_keys
	clientIDRe = regexp.MustCompile(`[0-9]{10,15}-[a-zA-Z0-9]+\.apps\.googleusercontent\.com`)

	// clientSecretRe is a regular expression that matches GCP OAuth2 client secrets.
	// There is no clear documentation on the exact format of GCP OAuth2 client secrets.
	// But most online references suggest they start with "GOCSPX-" prefix.
	// This is a good start as it reduces false positives.
	// References:
	// - https://gofastmcp.com/integrations/google
	// - https://web.archive.org/web/20250418010928/https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/google_oauth2_keys
	clientSecretRe = regexp.MustCompile(`\bGOCSPX-[a-zA-Z0-9_-]{10,40}`)
)

// detector implements OAuth2 client credentials detection.
type detector struct {
	maxSecretLen int
}

// NewDetector returns a detector that matches GCP OAuth2 client credentials.
func NewDetector() veles.Detector {
	return &detector{
		maxSecretLen: maxSecretLen,
	}
}

// MaxSecretLen returns the maximum length of secrets this detector can find.
func (d *detector) MaxSecretLen() uint32 {
	return uint32(d.maxSecretLen)
}

// Detect implements simple regex-based OAuth2 client credentials detection with proximity grouping.
func (d *detector) Detect(data []byte) ([]veles.Secret, []int) {
	clientIDs := findAllMatches(data, clientIDRe)
	clientSecrets := findAllMatches(data, clientSecretRe)

	pairs := findOptimalPairs(clientIDs, clientSecrets, d.maxSecretLen)
	secrets, positions := buildResults(clientIDs, clientSecrets, pairs)

	return secrets, positions
}

// match represents a regex match with its value and position.
type match struct {
	value    string
	position int
}

// findAllMatches finds all matches of a given regex in the given data.
func findAllMatches(data []byte, re *regexp.Regexp) []match {
	matches := re.FindAllSubmatchIndex(data, -1)
	var results []match
	for _, m := range matches {
		results = append(results, match{
			value:    string(data[m[0]:m[1]]),
			position: m[0],
		})
	}
	return results
}

// credentialPair represents a potential pairing between a client ID and client secret.
type credentialPair struct {
	clientIDIndex     int
	clientSecretIndex int
	distance          int
}

// findOptimalPairs finds the best pairing between client IDs and secrets using a greedy algorithm.
// It returns pairs that should be combined into ClientCredentials.
func findOptimalPairs(clientIDs, clientSecrets []match, maxDistance int) []credentialPair {
	// Find all possible pairings within maxContextLen distance
	possiblePairs := findPossiblePairs(clientIDs, clientSecrets, maxDistance)

	// Sort by distance (closest first)
	slices.SortFunc(possiblePairs, func(a, b credentialPair) int {
		return a.distance - b.distance
	})

	// Greedily select non-overlapping pairs
	var selectedPairs []credentialPair
	usedClientIDs := make(map[int]bool)
	usedClientSecrets := make(map[int]bool)

	for _, pair := range possiblePairs {
		if !usedClientIDs[pair.clientIDIndex] && !usedClientSecrets[pair.clientSecretIndex] {
			selectedPairs = append(selectedPairs, pair)
			usedClientIDs[pair.clientIDIndex] = true
			usedClientSecrets[pair.clientSecretIndex] = true
		}
	}

	return selectedPairs
}

// findPossiblePairs finds all client ID/secret pairs within the maximum context length.
func findPossiblePairs(clientIDs, clientSecrets []match, maxDistance int) []credentialPair {
	var possiblePairs []credentialPair
	for i, clientID := range clientIDs {
		for j, clientSecret := range clientSecrets {
			distance := abs(clientID.position - clientSecret.position)
			if distance <= maxDistance {
				possiblePairs = append(possiblePairs, credentialPair{
					clientIDIndex:     i,
					clientSecretIndex: j,
					distance:          distance,
				})
			}
		}
	}
	return possiblePairs
}

// buildResults constructs the final secrets and positions arrays from the pairing results.
func buildResults(clientIDs, clientSecrets []match, pairs []credentialPair) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var positions []int

	// Track which IDs and secrets have been used in pairs
	usedClientIDs := make(map[int]bool)
	usedClientSecrets := make(map[int]bool)

	// Add paired credentials
	for _, pair := range pairs {
		clientID := clientIDs[pair.clientIDIndex]
		clientSecret := clientSecrets[pair.clientSecretIndex]

		secrets = append(secrets, Credentials{
			ID:     clientID.value,
			Secret: clientSecret.value,
		})
		positions = append(positions, min(clientID.position, clientSecret.position))

		usedClientIDs[pair.clientIDIndex] = true
		usedClientSecrets[pair.clientSecretIndex] = true
	}

	return secrets, positions
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
