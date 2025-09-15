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
	"regexp"
	"sort"
	"strings"

	"github.com/google/osv-scalibr/veles"
)

// maxTokenLength is the maximum size of a Gitlab personal access token.
const maxTokenLength = 319

// Regular expressions for GitLab Personal Access Tokens:
//
// Based on the specs at: https://gitlab.com/gitlab-com/content-sites/handbook/-/blob/a5c49599bd88f1751616b40e4e32331aa2c8bf50/content/handbook/engineering/architecture/design-documents/cells/routable_tokens.md#L80
var (
	reRoutableVersioned = regexp.MustCompile(`glpat-[0-9A-Za-z_-]{27,300}\.[0-9a-z]{2}\.[0-9a-z]{2}[0-9a-z]{7}`)
	reRoutable          = regexp.MustCompile(`glpat-[0-9A-Za-z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}`)
	reLegacy            = regexp.MustCompile(`(glpat-[0-9A-Za-z_-]{20})`)
)

var _ veles.Detector = NewDetector()

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

	// Collect routable versioned matches
	for _, loc := range reRoutableVersioned.FindAllIndex(content, -1) {
		found = append(found, match{
			start: loc[0],
			end:   loc[1],
			token: string(content[loc[0]:loc[1]]),
		})
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
		secrets = append(secrets, GitlabPat{Pat: m.token})
		offsets = append(offsets, m.start)
	}
	return secrets, offsets
}
