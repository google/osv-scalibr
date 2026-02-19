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
	"cmp"
	"regexp"
	"slices"
	"sort"

	"github.com/google/osv-scalibr/veles"
)

var _ veles.Detector = &Detector{}

// Finder abstracts a function that returns all regex matches for one tuple
// component in the input buffer.
type Finder func([]byte) []Match

// Detector finds instances of a tuple of keys.
type Detector struct {
	MaxElementLen uint32
	MaxDistance   uint32
	Finders       []Finder
	FromTuple     func([]Match) (veles.Secret, bool)
	FromPartial   func(Match) (veles.Secret, bool)
}

// Detect implements the veles.Detector interface.
func (d *Detector) Detect(b []byte) ([]veles.Secret, []int) {
	if len(d.Finders) == 0 {
		return nil, nil
	}

	tuples, leftovers := d.collect(b)

	// validate before returning the best tuples (since some may be excluded at this step)
	var validTuples []*Tuple
	secretsFromTuple := make(map[*Tuple]veles.Secret)
	for _, t := range tuples {
		if secret, ok := d.FromTuple(t.Matches); ok {
			secretsFromTuple[t] = secret
			validTuples = append(validTuples, t)
		}
	}

	// if no valid tuple was returned check for partial
	if len(validTuples) == 0 && d.FromPartial != nil {
		var partials []Match
		for _, list := range leftovers {
			partials = append(partials, list...)
		}

		sort.Slice(partials, func(i, j int) bool {
			return partials[i].Start < partials[j].Start
		})

		var out []veles.Secret
		var pos []int
		for _, m := range partials {
			if s, ok := d.FromPartial(m); ok {
				out = append(out, s)
				pos = append(pos, m.Start)
			}
		}

		return out, pos
	}

	if len(validTuples) == 0 {
		return nil, nil
	}

	// from the valid tuples select the ones which minimize
	// the average distance between matches in tuples
	selected := d.selectTuples(validTuples)

	var out []veles.Secret
	var pos []int
	for _, t := range selected {
		out = append(out, secretsFromTuple[t])
		pos = append(pos, t.Start)
	}
	return out, pos
}

func (d *Detector) collect(b []byte) ([]*Tuple, [][]Match) {
	if len(d.Finders) == 0 {
		return nil, nil
	}

	all := make([][]Match, len(d.Finders))
	prev := []Match{}
	for i, f := range d.Finders {
		found := f(b)
		found = filterOverlaps(found, prev)
		if len(found) == 0 && d.FromPartial == nil {
			return nil, nil
		}
		all[i] = found
		prev = append(prev, found...)
	}

	res := d.generateTuples(all, 0, []Match{})
	return res, all
}

// filterOverlaps removes any matches in 'newMatches' that overlap with
// any of the matches in 'prevMatches'.
func filterOverlaps(newMatches, prevMatches []Match) []Match {
	var filtered []Match
	for _, m := range newMatches {
		if !slices.ContainsFunc(prevMatches, m.overlaps) {
			filtered = append(filtered, m)
		}
	}
	return filtered
}

func (d *Detector) generateTuples(all [][]Match, step int, currentMatches []Match) []*Tuple {
	if step == len(d.Finders) {
		t := buildTuple(currentMatches, int(d.MaxDistance))
		if t != nil {
			return []*Tuple{t}
		}
		return nil
	}

	var res []*Tuple
	for _, m := range all[step] {
		m.FinderIndex = step
		res = append(res, d.generateTuples(all, step+1, append(currentMatches, m))...)
	}
	return res
}

func buildTuple(matches []Match, maxGap int) *Tuple {
	if len(matches) == 0 {
		return nil
	}

	// Sort indexes instead of cloning matches to avoid allocations
	idxs := make([]int, len(matches))
	for i := range idxs {
		idxs[i] = i
	}
	slices.SortFunc(idxs, func(i, j int) int {
		return cmp.Compare(matches[i].Start, matches[j].Start)
	})

	firstIdx := idxs[0]
	start := matches[firstIdx].Start
	end := matches[firstIdx].End
	totalGap := 0
	for k := 1; k < len(matches); k++ {
		prev := matches[idxs[k-1]]
		curr := matches[idxs[k]]

		gap := curr.Start - prev.End
		if gap > maxGap {
			return nil
		}

		totalGap += gap
		if curr.End > end {
			end = curr.End
		}
	}

	return &Tuple{
		Matches: matches,
		Start:   start,
		End:     end,
		Dist:    totalGap,
	}
}

// Implementation of WIS (Weighted Interval Scheduling)
//
// Resources:
// - https://cs-people.bu.edu/januario/teaching/cs330/su23/slides/CS330-Lec10.pdf
// - https://algocademy.com/blog/job-scheduling-problem-mastering-the-weighted-interval-scheduling-algorithm/
func (d *Detector) selectTuples(candidates []*Tuple) []*Tuple {
	if len(candidates) == 0 {
		return nil
	}

	// Sort by End time to allow for O(log N) lookbacks
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].End < candidates[j].End
	})

	// dp[i] will store the optimal state up to the i-th candidate
	type state struct {
		count int
		dist  int
		prev  int  // To reconstruct the chosen tuples later
		take  bool // Did we include the i-th tuple in this optimal state?
	}
	dp := make([]state, len(candidates))

	for i := range candidates {
		// Option A: Skip this tuple (inherit optimal state from i-1)
		optSkip := state{count: 0, dist: 0, prev: -1, take: false}
		if i > 0 {
			optSkip = state{count: dp[i-1].count, dist: dp[i-1].dist, prev: i - 1, take: false}
		}

		// Option B: Take this tuple
		optTake := state{count: 1, dist: candidates[i].Dist, prev: -1, take: true}

		// Binary search to find the latest tuple that ends before candidates[i] starts
		// sort.Search returns the smallest index where the condition is true
		latestNonOverlapping := sort.Search(i, func(j int) bool {
			return candidates[j].End > candidates[i].Start
		}) - 1

		if latestNonOverlapping >= 0 {
			optTake.count = dp[latestNonOverlapping].count + 1
			optTake.dist = dp[latestNonOverlapping].dist + candidates[i].Dist
			optTake.prev = latestNonOverlapping
		}

		// Choose the best option: Maximize count, then minimize distance
		if optTake.count > optSkip.count || (optTake.count == optSkip.count && optTake.dist < optSkip.dist) {
			dp[i] = optTake
		} else {
			dp[i] = optSkip
		}
	}

	// Reconstruct the optimal path by walking backwards
	var result []*Tuple
	curr := len(candidates) - 1
	for curr >= 0 {
		if dp[curr].take {
			result = append(result, candidates[curr])
			curr = dp[curr].prev
		} else {
			curr-- // We skipped this one, just move back
		}
	}

	// Reverse the result since we collected it backwards
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result
}

// MaxSecretLen returns an upper bound on the total byte-span of a tuple.
func (d *Detector) MaxSecretLen() uint32 {
	numGaps := uint32(len(d.Finders) - 1)
	return d.MaxElementLen*uint32(len(d.Finders)) + (d.MaxDistance * numGaps)
}

// FindAllMatches returns a Finder that extracts all non-overlapping regex matches.
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

// FindAllMatchesGroup returns a Finder that extracts regex matches with group support.
func FindAllMatchesGroup(r *regexp.Regexp) Finder {
	return func(b []byte) []Match {
		idxs := r.FindAllSubmatchIndex(b, -1)
		matches := make([]Match, 0, len(idxs))

		for _, idx := range idxs {
			start, end := idx[0], idx[1]
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
