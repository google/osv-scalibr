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
	"slices"

	"github.com/google/osv-scalibr/veles"
)

type Match struct {
	Value    string
	Position int
}

type Pair struct {
	A        *Match
	B        *Match
	distance int
}

var _ veles.Detector = &Detector{}

// Detector finds instances of a pair of keys
type Detector struct {
	// The maximum length of the pair.
	MaxLen uint32
	// Function to use to search for matches
	FindA, FindB func(data []byte) []*Match
	// Returns a veles.Secret from a Match.
	//  It returns the secret and a boolean indicating success.
	FromPair func(Pair) (veles.Secret, bool)
}

// Detect implements veles.Detector.
func (d *Detector) Detect(data []byte) ([]veles.Secret, []int) {
	as, bs := d.FindA(data), d.FindB(data)
	return findOptimalPairs(as, bs, int(d.MaxLen), d.FromPair)
}

// MaxSecretLen implements veles.Detector.
func (d *Detector) MaxSecretLen() uint32 {
	return d.MaxLen
}

// findOptimalPairs finds the best pairing between client IDs and secrets using a greedy algorithm.
func findOptimalPairs(as, bs []*Match, maxLen int, fromPair func(Pair) (veles.Secret, bool)) ([]veles.Secret, []int) {
	// Find all possible pairings within maxContextLen distance
	possiblePairs := findPossiblePairs(as, bs, maxLen)

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
			secret, ok := fromPair(pair)
			if !ok {
				continue
			}
			secrets = append(secrets, secret)
			positions = append(positions, min(pair.A.Position, pair.B.Position))
			usedA[pair.A] = true
			usedB[pair.B] = true
		}
	}
	return secrets, positions
}

// findPossiblePairs finds all pairs within the maximum context length.
func findPossiblePairs(as, bs []*Match, maxLen int) []Pair {
	var possiblePairs []Pair
	for _, a := range as {
		for _, b := range bs {
			distance := abs(a.Position - b.Position)

			maxDistance := maxLen - len(a.Value)
			if a.Position < b.Position {
				maxDistance = maxLen - len(b.Value)
			}
			if distance <= maxDistance {
				possiblePairs = append(possiblePairs, Pair{A: a, B: b, distance: distance})
			}
		}
	}
	return possiblePairs
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
