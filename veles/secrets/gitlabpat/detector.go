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
	reRoutableVersioned = regexp.MustCompile(`(?P<prefix>glpat-)(?P<payload>[0-9A-Za-z_-]{27,300})\.(?P<version>[0-9a-z]{2})\.(?P<length>[0-9a-z]{2})(?P<crc>[0-9a-z]{7})`)
	reRoutable          = regexp.MustCompile(`glpat-[0-9A-Za-z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}`)
	reLegacy            = regexp.MustCompile(`glpat-[0-9A-Za-z_-]{20}`)
)

var _ veles.Detector = NewDetector()

// isValidCRC32 validates the CRC32 checksum of a GitLab Versioned Routable PAT.
// According to the documentation, the CRC32 is calculated on
// <prefix><base64-payload>.<token-version>.<base64-payload-length>
// and encoded as base36 with leading zeros to make 7 characters.
func isValidCRC32(prefix, payload, version, length, crcToCheck string) bool {
	// Construct the string to calculate CRC32 on
	checksumTarget := prefix + payload + "." + version + "." + length

	// Calculate CRC32 checksum
	crc := crc32.ChecksumIEEE([]byte(checksumTarget))

	// Convert to base36 string with leading zeros to make 7 characters
	calculatedCRC := strconv.FormatInt(int64(crc), 36)
	for len(calculatedCRC) < 7 {
		calculatedCRC = "0" + calculatedCRC
	}

	// Compare calculated CRC with the provided CRC
	return strings.EqualFold(calculatedCRC, crcToCheck)
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
		token string
	}

	var versionedMatches, routableMatches, legacyMatches []match

	// Collect routable versioned matches
	contentStr := string(content)
	for _, tokenMatchIndex := range reRoutableVersioned.FindAllStringSubmatchIndex(contentStr, -1) {
		versionedMatches = append(versionedMatches, match{
			start: tokenMatchIndex[0],
			token: contentStr[tokenMatchIndex[0]:tokenMatchIndex[1]],
		})
	}

	// Collect routable matches
	for _, loc := range reRoutable.FindAllIndex(content, -1) {
		routableMatches = append(routableMatches, match{
			start: loc[0],
			token: string(content[loc[0]:loc[1]]),
		})
	}

	// Collect legacy matches
	for _, loc := range reLegacy.FindAllIndex(content, -1) {
		legacyMatches = append(legacyMatches, match{
			start: loc[0],
			token: string(content[loc[0]:loc[1]]),
		})
	}

	var pruned []match

	// Always keep versioned tokens
	pruned = append(pruned, versionedMatches...)

	// Keep routable tokens only if they're not contained in any versioned token
	for _, routable := range routableMatches {
		contained := false
		for _, versioned := range versionedMatches {
			if strings.Contains(versioned.token, routable.token) {
				contained = true
				break
			}
		}
		if !contained {
			pruned = append(pruned, routable)
		}
	}

	// Keep legacy tokens only if they're not contained in any routable or versioned token
	for _, legacy := range legacyMatches {
		contained := false
		// Check against versioned tokens
		for _, versioned := range versionedMatches {
			if strings.Contains(versioned.token, legacy.token) {
				contained = true
				break
			}
		}
		// If not contained in versioned, check against routable
		if !contained {
			for _, routable := range routableMatches {
				if strings.Contains(routable.token, legacy.token) {
					contained = true
					break
				}
			}
		}
		if !contained {
			pruned = append(pruned, legacy)
		}
	}

	// Filter out invalid versioned tokens based on CRC32 validation
	finalMatches := make([]match, 0, len(pruned))
	for _, m := range pruned {
		if reRoutableVersioned.MatchString(m.token) {
			submatch := reRoutableVersioned.FindStringSubmatch(m.token)
			if len(submatch) == 6 &&
				isValidCRC32(submatch[1], submatch[2], submatch[3], submatch[4], submatch[5]) {
				finalMatches = append(finalMatches, m)
			}
		} else {
			finalMatches = append(finalMatches, m)
		}
	}

	// Sort by start offset to preserve document order
	sort.Slice(finalMatches, func(i, j int) bool { return finalMatches[i].start < finalMatches[j].start })

	secrets := make([]veles.Secret, 0, len(finalMatches))
	offsets := make([]int, 0, len(finalMatches))
	for _, m := range finalMatches {
		secrets = append(secrets, GitlabPAT{Pat: m.token})
		offsets = append(offsets, m.start)
	}
	return secrets, offsets
}
