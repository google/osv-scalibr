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

// Package simpleregex provides a simple regex & keyword sensitive information
// detector.
package simpleregex

import (
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
)

// Detector finds instances of sensitive information detector that matches the
// regular expression Re inside a chunk of text, and also has the keywords
// before or after the match.
// The detector will only work on plaintext data.
// It implements veles.Detector.
type Detector struct {
	// The maximum length of the sensitive information.
	MaxLen uint32
	MaxLen uint32
	// Matches on the sensitive information.
	Re *regexp.Regexp
	Re *regexp.Regexp

	// Context window size for keywords search before the match.
	ContextWindowBefore uint32
	ContextWindowBefore uint32
	// Context window size for keywords search after the match.
	ContextWindowAfter uint32
	ContextWindowAfter uint32

	// KeywordsRe is the regexp of the Keywords. All keywords are case insensitive.
	KeywordsRe *regexp.Regexp
	KeywordsRe *regexp.Regexp

	// Returns a sensitiveinformation.SensitiveInformation from a regexp match
	// result.
	FromMatch func([]byte, bool) (sensitiveinformation.SensitiveInformation, bool)
}

// KeywordsRe returns a regexp of the keywords. All keywords are case insensitive.
func KeywordsRe(keywords []string) *regexp.Regexp {
	if len(keywords) == 0 {
		return nil
	}
	return regexp.MustCompile("(?i)" + strings.Join(keywords, "|"))
}

// MaxSecretLen returns the maximum length of the search window.
func (d Detector) MaxSecretLen() uint32 {
	return d.MaxLen + d.ContextWindowBefore + d.ContextWindowAfter
	return d.MaxLen + d.ContextWindowBefore + d.ContextWindowAfter
}

// Detect finds candidate tokens that match Detector.Re and returns them
// alongside their starting positions.
func (d Detector) Detect(data []byte) (secrets []veles.Secret, positions []int) {
	for _, m := range d.Re.FindAllIndex(data, -1) {
	for _, m := range d.Re.FindAllIndex(data, -1) {
		l, r := m[0], m[1]
		lowerBound := max(0, l-int(d.ContextWindowBefore))
		upperBound := min(len(data), r+int(d.ContextWindowAfter))
		// If KeywordsRe is set, check if the keywords are present in the context
		// window before or after the match.
		contextMatch := d.KeywordsRe != nil &&
			(d.KeywordsRe.Match(data[lowerBound:l]) || d.KeywordsRe.Match(data[r:upperBound]))
		lowerBound := max(0, l-int(d.ContextWindowBefore))
		upperBound := min(len(data), r+int(d.ContextWindowAfter))
		// If KeywordsRe is set, check if the keywords are present in the context
		// window before or after the match.
		contextMatch := d.KeywordsRe != nil &&
			(d.KeywordsRe.Match(data[lowerBound:l]) || d.KeywordsRe.Match(data[r:upperBound]))

		if match, ok := d.FromMatch(data[l:r], contextMatch); ok {
		if match, ok := d.FromMatch(data[l:r], contextMatch); ok {
			secrets = append(secrets, match)
			positions = append(positions, l)
		}
	}
	return secrets, positions
}
