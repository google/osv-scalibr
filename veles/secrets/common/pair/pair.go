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

// Package pair contains common logic to find secret pairs
package pair

import (
	"regexp"
	"slices"

	"github.com/google/osv-scalibr/veles"
)

// Match contains information about a match
type Match struct {
	Start, End int
}

// Value returns the value of a match, empty string if the match is nil
func (m *Match) Value(data []byte) string {
	if m == nil {
		return ""
	}
	return string(data[m.Start:m.End])
}

// Pair contains two matches and their distance
type Pair struct {
	A        *Match
	B        *Match
	distance int
}

var _ veles.Detector = &Detector{}

// Detector finds instances of a pair of keys
type Detector struct {
	// The maximum length of an element in the pair.
	MaxElementLen uint32
	// MaxDistance sets the maximum distance between the matches.
	MaxDistance uint32
	// Function to use to search for matches.
	FindA, FindB func(data []byte) []*Match
	// Returns a veles.Secret from a Pair.
	// It returns the secret and a boolean indicating success.
	FromPair func([]byte, Pair) (veles.Secret, bool)
	// Returns a veles.Secret from a partial Pair.
	// It returns the secret and a boolean indicating success.
	FromPartialPair func([]byte, Pair) (veles.Secret, bool)
}

// Detect implements veles.Detector.
func (d *Detector) Detect(data []byte) ([]veles.Secret, []int) {
	as := d.FindA(data)
	// if FromPartialPair is not provided and no match was found for FindA early exit
	if d.FromPartialPair == nil && len(as) == 0 {
		return nil, nil
	}
	bs := d.FindB(data)
	bs = filterOverlapping(as, bs)
	return findOptimalPairs(as, bs, int(d.MaxDistance), data, d.FromPair, d.FromPartialPair)
}

// MaxSecretLen implements veles.Detector.
func (d *Detector) MaxSecretLen() uint32 {
	return d.MaxElementLen*2 + d.MaxDistance
}

// FindAllMatches returns a function which finds all matches of a given regex.
func FindAllMatches(re *regexp.Regexp) func(data []byte) []*Match {
	return func(data []byte) []*Match {
		matches := re.FindAllSubmatchIndex(data, -1)
		var results []*Match
		for _, m := range matches {
			results = append(results, &Match{
				Start: m[0],
				End:   m[1],
			})
		}
		return results
	}
}

// filterOverlapping filters overlapping matches, it expects both slices to be ordered
// and considers the first to be more important
//
// usage:
//
//	filtered_bs = filterOverlapping(as,bs)
func filterOverlapping(as, bs []*Match) []*Match {
	var filtered []*Match
	aIdx := 0

	for _, b := range bs {
		// Skip all A matches that end before B starts
		for aIdx < len(as) && as[aIdx].End <= b.Start {
			aIdx++
		}
		// If B does not overlap the current A, keep it
		if aIdx >= len(as) || b.Start < as[aIdx].Start {
			filtered = append(filtered, b)
		}
	}
	return filtered
}

// findOptimalPairs finds the best pairing between two sets of matches using a greedy algorithm.
func findOptimalPairs(as, bs []*Match, maxDistance int, data []byte, fromPair, fromPartialPair func([]byte, Pair) (veles.Secret, bool)) ([]veles.Secret, []int) {
	// Find all possible pairings within maxContextLen distance
	possiblePairs := findPossiblePairs(as, bs, maxDistance)

	// Sort by distance (closest first)
	slices.SortFunc(possiblePairs, func(a, b Pair) int {
		return a.distance - b.distance
	})

	// Greedily select non-overlapping pairs
	usedA := make(map[*Match]bool)
	usedB := make(map[*Match]bool)
	var secrets []veles.Secret
	var positions []int

	// select best match
	for _, pair := range possiblePairs {
		if !usedA[pair.A] && !usedB[pair.B] {
			secret, ok := fromPair(data, pair)
			if !ok {
				continue
			}
			secrets = append(secrets, secret)
			positions = append(positions, min(pair.A.Start, pair.B.Start))
			usedA[pair.A] = true
			usedB[pair.B] = true
		}
	}

	if fromPartialPair == nil {
		return secrets, positions
	}

	// leftover handling
	for _, a := range as {
		if !usedA[a] {
			secret, ok := fromPartialPair(data, Pair{A: a})
			if !ok {
				continue
			}
			secrets = append(secrets, secret)
			positions = append(positions, a.Start)
		}
	}

	for _, b := range bs {
		if !usedB[b] {
			secret, ok := fromPartialPair(data, Pair{B: b})
			if !ok {
				continue
			}
			secrets = append(secrets, secret)
			positions = append(positions, b.Start)
		}
	}

	return secrets, positions
}

// findPossiblePairs finds all pairs within the maximum context length.
func findPossiblePairs(as, bs []*Match, maxDistance int) []Pair {
	var possiblePairs []Pair
	for _, a := range as {
		for _, b := range bs {
			distance := b.Start - (a.End)
			if a.Start > b.Start {
				distance = a.Start - (b.End)
			}

			// Skip overlapping matches
			// - hard check to prevent errors
			// - overlapping should be handled before reaching this point
			if distance < 0 {
				continue
			}

			// Include pair if within maxDistance
			if distance <= maxDistance {
				possiblePairs = append(possiblePairs, Pair{A: a, B: b, distance: distance})
			}
		}
	}
	return possiblePairs
}
