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

// Package pair contains common logic to find secret pairs
package pair

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

// Match contains information about a match
type Match struct {
	Start int
	Value []byte
}

func (m Match) end() int {
	return m.Start + len(m.Value)
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
	// FindA is a function that searches for the first element of a pair in the data.
	// It should generally apply stricter matching rules than FindB. Its results are used to:
	//  - filter out overlapping matches (removing conflicting matches from FindB)
	//  - allow early termination if no matches are found.
	FindA func(data []byte) []*Match
	// FindB is a function that searches for the second element of a pair in the data.
	FindB func(data []byte) []*Match
	// Returns a veles.Secret from a Pair.
	// It returns the secret and a boolean indicating success.
	FromPair func(Pair) (veles.Secret, bool)
	// Returns a veles.Secret from a partial Pair.
	// It returns the secret and a boolean indicating success.
	FromPartialPair func(Pair) (veles.Secret, bool)
}

// Detect implements veles.Detector by delegating to the ntuple engine.
func (d *Detector) Detect(data []byte) ([]veles.Secret, []int) {
	// ntuple finders return ntuple.Match with FinderIndex preserved
	findA := func(b []byte) []ntuple.Match {
		as := d.FindA(b)
		out := make([]ntuple.Match, len(as))
		for i, m := range as {
			out[i] = ntuple.Match{
				Start:       m.Start,
				End:         m.end(),
				Value:       m.Value,
				FinderIndex: 0,
			}
		}
		return out
	}

	findB := func(b []byte) []ntuple.Match {
		bs := d.FindB(b)
		out := make([]ntuple.Match, len(bs))
		for i, m := range bs {
			out[i] = ntuple.Match{
				Start:       m.Start,
				End:         m.end(),
				Value:       m.Value,
				FinderIndex: 1,
			}
		}
		return out
	}

	nd := &ntuple.Detector{
		MaxElementLen: d.MaxElementLen,
		MaxDistance:   d.MaxDistance,
		Finders:       []ntuple.Finder{findA, findB},

		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			var a, b ntuple.Match

			for _, m := range ms {
				if m.FinderIndex == 0 {
					a = m
				} else {
					b = m
				}
			}

			p := Pair{
				A:        &Match{Start: a.Start, Value: a.Value},
				B:        &Match{Start: b.Start, Value: b.Value},
				distance: b.Start - (a.Start + len(a.Value)),
			}

			return d.FromPair(p)
		},
	}

	// Partial match support
	if d.FromPartialPair != nil {
		nd.FromPartial = func(m ntuple.Match) (veles.Secret, bool) {
			if m.FinderIndex == 0 {
				return d.FromPartialPair(Pair{
					A: &Match{Start: m.Start, Value: m.Value},
				})
			}
			return d.FromPartialPair(Pair{
				B: &Match{Start: m.Start, Value: m.Value},
			})
		}
	}

	return nd.Detect(data)
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
				Value: data[m[0]:m[1]],
			})
		}
		return results
	}
}
