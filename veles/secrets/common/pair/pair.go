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

// FindOptimalPairs finds the best pairing between client IDs and secrets using a greedy algorithm.
func FindOptimalPairs(as, bs []*Match, maxDistance int, fromPair func(Pair) veles.Secret) ([]veles.Secret, []int) {
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
			secrets = append(secrets, fromPair(pair))
			positions = append(positions, min(pair.A.Position, pair.B.Position))
			usedA[pair.A] = true
			usedB[pair.B] = true
		}
	}

	return secrets, positions
}

// findPossiblePairs finds all pairs within the maximum context length.
func findPossiblePairs(as, bs []*Match, maxDistance int) []Pair {
	var possiblePairs []Pair
	for _, a := range as {
		for _, b := range bs {
			distance := abs(a.Position - b.Position)
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
