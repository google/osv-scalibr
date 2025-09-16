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

// Package gitlabpat contains a Veles Secret type and a Detector for
// Gitlab Personal Access Tokens (prefix `glpat-`).
package gitlabpat

import (
	"hash/crc32"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/osv-scalibr/veles"
)

// maxTokenLength is the maximum size of a Gitlab personal access token.
const maxTokenLength = 319

// Regular expressions for GitLab Personal Access Tokens:
//
// Based on the specs at: https://gitlab.com/gitlab-com/content-sites/handbook/-/blob/a5c49599bd88f1751616b40e4e32331aa2c8bf50/content/handbook/engineering/architecture/design-documents/cells/routable_tokens.md#L80
var (
	reRoutableVersioned = regexp.MustCompile(`(?P<prefix>glpat-)(?P<payload>[0-9A-Za-z_-]{27,300})\.[0-9a-z]{2}\.(?P<length>[0-9a-z]{2})(?P<crc>[0-9a-z]{7})`)
	reRoutable          = regexp.MustCompile(`glpat-[0-9A-Za-z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}`)
	reLegacy            = regexp.MustCompile(`glpat-[0-9A-Za-z_-]{20}`)
)

var _ veles.Detector = NewDetector()

// isValidCRC32 validates the CRC32 checksum of a GitLab PAT.
// According to the documentation, the CRC32 is calculated on <prefix><base64-payload>.<base64-payload-length>
// and encoded as base36 with leading zeros to make 7 characters.
func isValidCRC32(prefix, payload, lengthHex, crcHex string) bool {
	// Construct the string to calculate CRC32 on
	checksumTarget := prefix + payload + "." + lengthHex

	// Calculate CRC32 checksum
	crc := crc32.ChecksumIEEE([]byte(checksumTarget))

	// Convert to base36 string with leading zeros to make 7 characters
	calculatedCRC := strconv.FormatInt(int64(crc), 36)
	for len(calculatedCRC) < 7 {
		calculatedCRC = "0" + calculatedCRC
	}

	// Compare calculated CRC with the provided CRC
	return strings.EqualFold(calculatedCRC, crcHex)
}

// detector is a Veles Detector.
type detector struct{}

// NewDetector returns a new Detector that matches
// Gitlab Personal Access Tokens.
func NewDetector() veles.Detector {
	return &detector{}
}

func (d *detector) MaxSecretLen() uint32 {
	return maxTokenLength
}

func (d *detector) Detect(content []byte) ([]veles.Secret, []int) {
	type match struct {
		start int
		end   int
		token string
	}
	var found []match
	// tokens with invalid CRC32 checksum
	var blacklist []string

	// Collect routable versioned matches using string matching
	contentStr := string(content)
	for i, tokenMatch := range reRoutableVersioned.FindAllStringSubmatch(contentStr, -1) {
		subexpNames := reRoutableVersioned.SubexpNames()
		var prefixValue, payloadValue, lengthValue, crcValue string
		for i, name := range subexpNames {
			if i == 0 {
				continue
			}
			switch name {
			case "prefix":
				prefixValue = tokenMatch[i]
			case "payload":
				payloadValue = tokenMatch[i]
			case "length":
				lengthValue = tokenMatch[i]
			case "crc":
				crcValue = tokenMatch[i]
			}
		}

		token := tokenMatch[0]
		matchIndices := reRoutableVersioned.FindAllStringSubmatchIndex(contentStr, -1)[i]
		start, end := matchIndices[0], matchIndices[1]

		if isValidCRC32(prefixValue, payloadValue, lengthValue, crcValue) {
			found = append(found, match{
				start: start,
				end:   end,
				token: token,
			})
		} else {
			// this token can be still matched by legacy regex
			// we need to blacklist it
			blacklist = append(blacklist, token)
		}
	}

	// Collect routable matches
	for _, loc := range reRoutable.FindAllIndex(content, -1) {
		found = append(found, match{
			start: loc[0],
			end:   loc[1],
			token: string(content[loc[0]:loc[1]]),
		})
	}

	// Collect legacy matches
	for _, loc := range reLegacy.FindAllIndex(content, -1) {
		found = append(found, match{
			start: loc[0],
			end:   loc[1],
			token: string(content[loc[0]:loc[1]]),
		})
	}

	// Remove matches that are strictly contained within another match (e.g., legacy inside routable)
	// here we check if 'm'(shorter string match) is inside 'n'
	pruned := make([]match, 0, len(found))
	for i, m := range found {
		contained := false
		invalidCrc32 := false
		// check if it is not contained in a longer match with invalid crc32 checksum
		for _, bl := range blacklist {
			if strings.Contains(bl, m.token) {
				invalidCrc32 = true
				break
			}
		}
		if invalidCrc32 {
			break
		}
		for j, n := range found {
			if i == j {
				continue
			}
			if len(n.token) > len(m.token) && strings.Contains(n.token, m.token) {
				contained = true
				break
			}
		}
		if !contained {
			pruned = append(pruned, m)
		}
	}

	// Sort by start offset to preserve document order
	sort.Slice(pruned, func(i, j int) bool { return pruned[i].start < pruned[j].start })

	secrets := make([]veles.Secret, 0, len(pruned))
	offsets := make([]int, 0, len(pruned))
	for _, m := range pruned {
		secrets = append(secrets, GitlabPAT{Pat: m.token})
		offsets = append(offsets, m.start)
	}
	return secrets, offsets
}
