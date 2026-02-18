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

// Package ntuple provides a generic mechanism to detect ordered tuples of
// related secrets (e.g., access key + client ID + client secret) within a raw
// byte buffer. It allows individual elements of the tuple to be matched using
// independent regular expressions and then combines these matches into
// consistent ordered tuples based on occurrence and distance rules.
package ntuple

import (
	"math"
	"regexp"
	"sort"

	"github.com/google/osv-scalibr/veles"
)

// Match describes a single regex match for one element of a tuple.
type Match struct {
	Start       int
	End         int
	Value       []byte
	FinderIndex int
}

// Tuple represents a completed grouping of individual matches.
type Tuple struct {
	Matches []Match
	Start   int
	End     int
	Dist    int
}

var _ veles.Detector = &Detector{}

// Detector finds instances of a tuple of keys.
type Detector struct {
	MaxElementLen uint32
	MaxDistance   uint32
	Finders       []Finder
	FromTuple     func([]Match) (veles.Secret, bool)
	FromPartial   func(Match) (veles.Secret, bool)
}

// Finder abstracts a function that returns all regex matches for one tuple
// component in the input buffer.
type Finder func([]byte) []Match

// Detect implements the veles.Detector interface.
func (d *Detector) Detect(b []byte) ([]veles.Secret, []int) {
	if len(d.Finders) == 0 {
		return nil, nil
	}

	// Generate all matches
	all := make([][]Match, len(d.Finders))
	for i, f := range d.Finders {
		matches := f(b)
		if len(matches) == 0 && d.FromPartial == nil {
			return nil, nil
		}
		for j := range matches {
			matches[j].FinderIndex = i
		}
		all[i] = matches
	}

	candidates := collectAllTuples(all, int(d.MaxDistance))

	// Validate tuples before selecting the best ones
	var validCandidates []*Tuple
	cachedSecrets := make(map[*Tuple]veles.Secret)

	for _, t := range candidates {
		if secret, ok := d.FromTuple(t.Matches); ok {
			cachedSecrets[t] = secret
			validCandidates = append(validCandidates, t)
		}
	}

	if len(validCandidates) > 0 {
		selected := selectTuples(validCandidates)

		var out []veles.Secret
		var pos []int

		if len(selected) > 0 {
			// TODO: remove this if it's needed just for testing
			sort.Slice(selected, func(i, j int) bool {
				return selected[i].Start < selected[j].Start
			})

			for _, t := range selected {
				out = append(out, cachedSecrets[t])
				pos = append(pos, t.Start)
			}
		}
		return out, pos
	}

	if d.FromPartial == nil {
		return nil, nil
	}

	var out []veles.Secret
	var pos []int
	var partials []Match
	for _, list := range all {
		partials = append(partials, list...)
	}
	sort.Slice(partials, func(i, j int) bool {
		return partials[i].Start < partials[j].Start
	})

	for _, m := range partials {
		if s, ok := d.FromPartial(m); ok {
			out = append(out, s)
			pos = append(pos, m.Start)
		}
	}

	return out, pos
}

// buildTuple validates the tuple and sets the Start/End based on physical layout.
//
// TODO: i don't like this
func buildTuple(matches []Match, maxDist int) *Tuple {
	n := len(matches)
	if n == 0 {
		return nil
	}

	// 1. Sort matches by Start position to understand physical layout.
	// This is required to correctly calculate pair-wise gaps and total span.
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Start < matches[j].Start
	})

	// 2. Capture MinStart and MaxEnd from the sorted physical layout.
	minStart := matches[0].Start
	maxEnd := matches[0].End
	totalGap := 0

	// 3. Iterate to check overlaps and pair-wise distance constraints.
	for i := range n - 1 {
		curr := matches[i]
		next := matches[i+1]

		// Overlap Check
		if rangesOverlap(curr.Start, curr.End, next.Start, next.End) {
			return nil
		}

		// Distance Check: Ensure the gap between THIS pair is within limit.
		gap := next.Start - curr.End
		if gap > maxDist {
			return nil
		}

		totalGap += gap
		if next.End > maxEnd {
			maxEnd = next.End
		}
	}

	// 4. Restore FinderIndex order.
	// The Matches slice in the Tuple must match the order of Finders (0, 1, 2...)
	// so that FromTuple receives arguments in the expected order.
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].FinderIndex < matches[j].FinderIndex
	})

	return &Tuple{
		Matches: matches,
		Start:   minStart,
		End:     maxEnd,
		Dist:    totalGap,
	}
}

// selectTuples selects the best non-overlapping subset of tuples.
func selectTuples(candidates []*Tuple) []*Tuple {
	if len(candidates) == 0 {
		return nil
	}

	type candidateInfo struct {
		tuple     *Tuple
		conflicts []int
		consumed  bool
	}

	infos := make([]*candidateInfo, len(candidates))
	for i := range candidates {
		infos[i] = &candidateInfo{tuple: candidates[i]}
	}

	// Build Conflict Graph
	for i := range infos {
		for j := i + 1; j < len(infos); j++ {
			if tuplesOverlap(infos[i].tuple, infos[j].tuple) {
				infos[i].conflicts = append(infos[i].conflicts, j)
				infos[j].conflicts = append(infos[j].conflicts, i)
			}
		}
	}

	var result []*Tuple

	// Greedy Selection Loop
	for {
		bestIdx := -1
		minConflicts := math.MaxInt32
		minDist := math.MaxInt32

		activeCount := 0

		for i, info := range infos {
			if info.consumed {
				continue
			}
			activeCount++

			currentConflicts := 0
			for _, neighborIdx := range info.conflicts {
				if !infos[neighborIdx].consumed {
					currentConflicts++
				}
			}

			// Prioritize: Min Conflicts -> Min Distance
			isBetter := false
			if currentConflicts < minConflicts {
				isBetter = true
			} else if currentConflicts == minConflicts {
				if info.tuple.Dist < minDist {
					isBetter = true
				}
			}

			if isBetter {
				bestIdx = i
				minConflicts = currentConflicts
				minDist = info.tuple.Dist
			}
		}

		if activeCount == 0 || bestIdx == -1 {
			break
		}

		winner := infos[bestIdx]
		result = append(result, winner.tuple)

		winner.consumed = true
		for _, neighborIdx := range winner.conflicts {
			infos[neighborIdx].consumed = true
		}
	}

	return result
}

func tuplesOverlap(a, b *Tuple) bool {
	for _, mA := range a.Matches {
		for _, mB := range b.Matches {
			if rangesOverlap(mA.Start, mA.End, mB.Start, mB.End) {
				return true
			}
		}
	}
	return false
}

func collectAllTuples(all [][]Match, maxDistance int) []*Tuple {
	if len(all) == 0 {
		return nil
	}
	return generateTuples(all, 0, nil, maxDistance)
}

func generateTuples(all [][]Match, idx int, current []Match, maxDist int) []*Tuple {
	if idx == len(all) {
		// Pass a COPY of current matches to buildTuple to ensure isolation
		t := buildTuple(append([]Match(nil), current...), maxDist)
		if t != nil {
			return []*Tuple{t}
		}
		return nil
	}

	var out []*Tuple
	for _, m := range all[idx] {
		tmp := make([]Match, len(current)+1)
		copy(tmp, current)
		tmp[len(current)] = m

		sub := generateTuples(all, idx+1, tmp, maxDist)
		out = append(out, sub...)
	}
	return out
}

func rangesOverlap(a1, a2, b1, b2 int) bool {
	return a1 < b2 && b1 < a2
}

// MaxSecretLen returns an upper bound on the total byte-span of a tuple.
// Each tuple consists of exactly one element from each Finder. We assume
// each element may be up to MaxElementLen bytes long, so the total possible
// payload size is MaxElementLen * len(d.Finders).
//
// In addition, tuple construction allows the elements to be separated by
// up to MaxDistance bytes, where MaxDistance is defined as the difference
// between the latest start position and the earliest end position of the
// matched elements. This represents a single contiguous gap spanning from
// the first match to the last match, not one gap per element.
//
// Therefore, the maximum total span of a tuple is:
// MaxElementLen * len(d.Finders) + MaxDistance.
func (d *Detector) MaxSecretLen() uint32 {
	numGaps := uint32(len(d.Finders) - 1)
	return d.MaxElementLen*uint32(len(d.Finders)) + (d.MaxDistance * numGaps)
}

// FindAllMatches returns a Finder that extracts all non-overlapping regex
// matches using r.FindAllIndex. Each match is converted into a Match with
// absolute byte positions.
func FindAllMatches(r *regexp.Regexp) Finder {
	return func(b []byte) []Match {
		idxs := r.FindAllIndex(b, -1)
		matches := make([]Match, 0, len(idxs))
		for _, idx := range idxs {
			matches = append(matches, Match{
				Start: idx[0],
				End:   idx[1],
				Value: b[idx[0]:idx[1]],
			})
		}
		return matches
	}
}

// FindAllMatchesGroup returns a Finder that extracts regex matches similarly to
// FindAllMatches, but with support for context-aware capture groups.
//
// If the provided regexp contains at least one capturing group and that group
// matches, the span of the *first* capturing group is returned as the Match.
// Otherwise, the span of the full match is used as a fallback.
//
// This is intended for secret-detection use cases where the regex includes
// surrounding context (e.g. "client_secret", "refresh_token") to reduce false
// positives, but only the secret value itself should be returned.
//
// For example, given a regexp like:
//
//	(?:client_secret\s*[:=]\s*)([A-Za-z0-9]{30,})
//
// the full match includes the context, but only the captured secret value
// ([A-Za-z0-9]{30,}) is returned in Match.Value.
//
// This function is fully backward-compatible and opt-in; existing detectors
// using FindAllMatches are unaffected.
func FindAllMatchesGroup(r *regexp.Regexp) Finder {
	return func(b []byte) []Match {
		idxs := r.FindAllSubmatchIndex(b, -1)
		matches := make([]Match, 0, len(idxs))

		for _, idx := range idxs {
			// idx layout:
			// [fullStart, fullEnd, g1Start, g1End, g2Start, g2End, ...]
			start, end := idx[0], idx[1]

			// If group 1 exists and matched, prefer it
			if len(idx) >= 4 && idx[2] >= 0 && idx[3] >= 0 {
				start, end = idx[2], idx[3]
			}

			matches = append(matches, Match{
				Start: start,
				End:   end,
				Value: b[start:end],
			})
		}
		return matches
	}
}
