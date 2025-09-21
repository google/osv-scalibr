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

	"github.com/google/osv-scalibr/veles"
)

const (
	// maxContextLen is the maximum number of bytes to group related client IDs and secrets.
	// Although Client ID and Client Secret are not long, they can appear in files far apart from each other.
	// Seaching blocks of 10 KiB should be sufficient to find related credentials.
	maxContextLen = 10 * 1 << 10 // 10 KiB
)

var (
	// clientIDRe is a regular expression that matches GCP OAuth2 client IDs.
	// There is no official documentation on the exact format of GCP OAuth2 client IDs.
	// But example on official docs include examples that end with .apps.googleusercontent.com:
	// - https://developers.google.com/identity/protocols/oauth2/web-server
	//
	// Other references also suggest similar formats:
	// - https://gofastmcp.com/integrations/google
	// - https://web.archive.org/web/20250418010928/https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/google_oauth2_keys
	clientIDRe = regexp.MustCompile(`[0-9]{10,15}-[a-zA-Z0-9_-]+\.apps\.googleusercontent\.com`)

	// clientSecretRe is a regular expression that matches GCP OAuth2 client secrets.
	// There is no clear documentation on the exact format of GCP OAuth2 client secrets.
	// But most online references suggest they start with "GOCSPX-" prefix.
	// This is a good start as it reduces false positives.
	// References:
	// - https://gofastmcp.com/integrations/google
	// - https://web.archive.org/web/20250418010928/https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/google_oauth2_keys
	clientSecretRe = regexp.MustCompile(`GOCSPX-[a-zA-Z0-9_-]{10,40}`)
)

// detector implements OAuth2 client credentials detection.
type detector struct {
	maxContextLen int
}

// match represents a regex match with its value and position.
type match struct {
	value    string
	position int
}

// NewDetector returns a detector that matches GCP OAuth2 client credentials.
func NewDetector() veles.Detector {
	return &detector{
		maxContextLen: maxContextLen,
	}
}

// MaxSecretLen returns the maximum length of secrets this detector can find.
func (d *detector) MaxSecretLen() uint32 {
	return uint32(d.maxContextLen)
}

// Detect implements simple regex-based OAuth2 client credentials detection with proximity grouping.
func (d *detector) Detect(data []byte) ([]veles.Secret, []int) {
	clientIDs := d.findAllClientIDs(data)
	clientSecrets := d.findAllClientSecrets(data)

	pairs := d.findOptimalPairs(clientIDs, clientSecrets)
	secrets, positions := d.buildResults(clientIDs, clientSecrets, pairs)

	return secrets, positions
}

// findAllClientIDs extracts all valid client ID matches from the data.
func (d *detector) findAllClientIDs(data []byte) []match {
	matches := clientIDRe.FindAllSubmatchIndex(data, -1)
	var clientIDs []match
	for _, m := range matches {
		clientIDs = append(clientIDs, match{
			value:    string(data[m[0]:m[1]]),
			position: m[0],
		})
	}
	return clientIDs
}

// findAllClientSecrets extracts all valid client secret matches from the data.
func (d *detector) findAllClientSecrets(data []byte) []match {
	matches := clientSecretRe.FindAllSubmatchIndex(data, -1)
	var clientSecrets []match
	for _, m := range matches {
		clientSecrets = append(clientSecrets, match{
			value:    string(data[m[0]:m[1]]),
			position: m[0],
		})
	}
	return clientSecrets
}

// credentialPair represents a potential pairing between a client ID and client secret.
type credentialPair struct {
	clientIDIndex     int
	clientSecretIndex int
	distance          int
}

// findOptimalPairs finds the best pairing between client IDs and secrets using a greedy algorithm.
// It returns pairs that should be combined into ClientCredentials.
func (d *detector) findOptimalPairs(clientIDs, clientSecrets []match) []credentialPair {
	// Find all possible pairings within maxContextLen distance
	possiblePairs := d.findPossiblePairs(clientIDs, clientSecrets)

	// Sort by distance (closest first)
	d.sortPairsByDistance(possiblePairs)

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
func (d *detector) findPossiblePairs(clientIDs, clientSecrets []match) []credentialPair {
	var possiblePairs []credentialPair
	for i, clientID := range clientIDs {
		for j, clientSecret := range clientSecrets {
			distance := abs(clientID.position - clientSecret.position)
			if distance <= d.maxContextLen {
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

// sortPairsByDistance sorts credential pairs by distance using a simple bubble sort.
func (d *detector) sortPairsByDistance(pairs []credentialPair) {
	for i := 0; i < len(pairs); i++ {
		for j := i + 1; j < len(pairs); j++ {
			if pairs[j].distance < pairs[i].distance {
				pairs[i], pairs[j] = pairs[j], pairs[i]
			}
		}
	}
}

// buildResults constructs the final secrets and positions arrays from the pairing results.
func (d *detector) buildResults(clientIDs, clientSecrets []match, pairs []credentialPair) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var positions []int

	// Track which IDs and secrets have been used in pairs
	usedClientIDs := make(map[int]bool)
	usedClientSecrets := make(map[int]bool)

	// Add paired credentials
	for _, pair := range pairs {
		clientID := clientIDs[pair.clientIDIndex]
		clientSecret := clientSecrets[pair.clientSecretIndex]

		secrets = append(secrets, ClientCredentials{
			ClientID:     clientID.value,
			ClientSecret: clientSecret.value,
		})
		positions = append(positions, minInt(clientID.position, clientSecret.position))

		usedClientIDs[pair.clientIDIndex] = true
		usedClientSecrets[pair.clientSecretIndex] = true
	}

	// Add unpaired client IDs
	for i, clientID := range clientIDs {
		if !usedClientIDs[i] {
			secrets = append(secrets, ClientCredentials{
				ClientID: clientID.value,
			})
			positions = append(positions, clientID.position)
		}
	}

	// Add unpaired client secrets
	for i, clientSecret := range clientSecrets {
		if !usedClientSecrets[i] {
			secrets = append(secrets, ClientCredentials{
				ClientSecret: clientSecret.value,
			})
			positions = append(positions, clientSecret.position)
		}
	}

	return secrets, positions
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
