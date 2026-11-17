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

package ntuple_test

import (
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

type mockSecret struct {
	Value string
}

// implement veles.Secret
func (m mockSecret) ValueBytes() []byte { return []byte(m.Value) }

// full tuple converter
func mockSecretFromTuple(ms []ntuple.Match) (veles.Secret, bool) {
	var a ntuple.Match
	var b ntuple.Match
	var c ntuple.Match

	for j := range ms {
		switch ms[j].FinderIndex {
		case 0:
			a = ms[j]
		case 1:
			b = ms[j]
		default:
			c = ms[j]
		}
	}

	if len(ms) == 3 {
		return mockSecret{
			Value: string(a.Value) + "-" + string(b.Value) + "-" + string(c.Value),
		}, true
	}
	return nil, false
}

// partial tuple converter
func mockSecretFromPartial(m ntuple.Match) (veles.Secret, bool) {
	return mockSecret{Value: string(m.Value)}, true
}

func TestNTupleDetection(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		maxDistance uint32
		fromPartial func(ntuple.Match) (veles.Secret, bool)
		want        []veles.Secret
		wantPos     []int
	}{
		{
			name:        "simple_triple",
			input:       "a1 b1 c1",
			maxDistance: 1000,
			want: []veles.Secret{
				mockSecret{Value: "a1-b1-c1"},
			},
			wantPos: []int{0},
		},
		{
			name:        "multiple_triples",
			input:       "a1 b1 c1   a2 b2 c2",
			maxDistance: 1000,
			want: []veles.Secret{
				mockSecret{Value: "a1-b1-c1"},
				mockSecret{Value: "a2-b2-c2"},
			},
			wantPos: []int{0, 11},
		},
		{
			name:        "missing_c - no full tuple",
			input:       "a1 b1",
			maxDistance: 1000,
			want:        nil,
		},
		{
			name:        "far_apart - no tuple",
			input:       "a1           b1          c1",
			maxDistance: 5,
			want:        nil,
		},
		{
			name:        "partial_allowed",
			input:       "a1",
			maxDistance: 1000,
			fromPartial: mockSecretFromPartial,
			want: []veles.Secret{
				mockSecret{Value: "a1"},
			},
			wantPos: []int{0},
		},
		{
			name:        "overlap_resolution",
			input:       " b2 ab1 c1",
			maxDistance: 1000,
			fromPartial: mockSecretFromPartial,
			want: []veles.Secret{
				mockSecret{Value: "ab1-b2-c1"},
			},
			wantPos: []int{1},
		},
		{
			name:        "closest_pairing",
			input:       " a2 a1 b1 c1",
			maxDistance: 1000,
			want: []veles.Secret{
				mockSecret{Value: "a1-b1-c1"},
			},
			wantPos: []int{4},
		},
		{
			name:        "zero_distance",
			input:       "a1",
			maxDistance: 0,
			fromPartial: mockSecretFromPartial,
			want: []veles.Secret{
				mockSecret{Value: "a1"},
			},
			wantPos: []int{0},
		},
		{
			name:        "no_reuse_after_tuple_consumed",
			input:       "a1 b1 c1  a2 b1 c2",
			maxDistance: 2,
			want: []veles.Secret{
				mockSecret{Value: "a1-b1-c1"},
				mockSecret{Value: "a2-b1-c2"},
			},
			wantPos: []int{0, 10},
		},
		{
			name:        "partial_matches_with_finderindex_filter",
			input:       "a1 b1",
			maxDistance: 1000,
			fromPartial: func(m ntuple.Match) (veles.Secret, bool) {
				// Only return matches from Finder 0 (a pattern)
				if m.FinderIndex == 0 {
					return mockSecret{Value: string(m.Value)}, true
				}
				return nil, false
			},
			want: []veles.Secret{
				mockSecret{Value: "a1"},
			},
			wantPos: []int{0},
		},
		{
			name:        "partial_matches_multiple_finders",
			input:       "a1 b1 c1",
			maxDistance: 0, // Force no tuple formation
			fromPartial: func(m ntuple.Match) (veles.Secret, bool) {
				// Return all partial matches with their FinderIndex
				return mockSecret{Value: string(m.Value) + "@" + string(rune('0'+m.FinderIndex))}, true
			},
			want: []veles.Secret{
				mockSecret{Value: "a1@0"},
				mockSecret{Value: "b1@1"},
				mockSecret{Value: "c1@2"},
			},
			wantPos: []int{0, 3, 6},
		},
	}

	aPattern := regexp.MustCompile(`a[a-z]*[0-9]`)
	bPattern := regexp.MustCompile(`b[a-z]*[0-9]`)
	cPattern := regexp.MustCompile(`c[a-z]*[0-9]`)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &ntuple.Detector{
				MaxElementLen: 10,
				MaxDistance:   tt.maxDistance,
				Finders: []ntuple.Finder{
					ntuple.FindAllMatches(aPattern),
					ntuple.FindAllMatches(bPattern),
					ntuple.FindAllMatches(cPattern),
				},
				FromTuple:   mockSecretFromTuple,
				FromPartial: tt.fromPartial,
			}

			got, pos := d.Detect([]byte(tt.input))

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Secrets mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantPos, pos); diff != "" {
				t.Errorf("Positions mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestFinderIndexSetForPartials verifies that FinderIndex is correctly set
// for partial matches (leftovers that don't form complete tuples).
// This is a regression test for a bug where FinderIndex was not set,
// causing all partial matches to have FinderIndex=0 (the zero value).
func TestFinderIndexSetForPartials(t *testing.T) {
	aPattern := regexp.MustCompile(`a[0-9]`)
	bPattern := regexp.MustCompile(`b[0-9]`)
	cPattern := regexp.MustCompile(`c[0-9]`)

	tests := []struct {
		name              string
		input             string
		wantFinderIndexes []int // Expected FinderIndex for each partial match
		wantValues        []string
	}{
		{
			name:              "only_first_finder_matches",
			input:             "a1",
			wantFinderIndexes: []int{0},
			wantValues:        []string{"a1"},
		},
		{
			name:              "only_second_finder_matches",
			input:             "b1",
			wantFinderIndexes: []int{1},
			wantValues:        []string{"b1"},
		},
		{
			name:              "only_third_finder_matches",
			input:             "c1",
			wantFinderIndexes: []int{2},
			wantValues:        []string{"c1"},
		},
		{
			name:              "first_and_second_match_no_third",
			input:             "a1 b1",
			wantFinderIndexes: []int{0, 1},
			wantValues:        []string{"a1", "b1"},
		},
		{
			name:              "all_three_but_too_far_apart",
			input:             "a1                    b1                    c1",
			wantFinderIndexes: []int{0, 1, 2},
			wantValues:        []string{"a1", "b1", "c1"},
		},
		{
			name:              "multiple_matches_from_same_finder",
			input:             "a1 a2 a3",
			wantFinderIndexes: []int{0, 0, 0},
			wantValues:        []string{"a1", "a2", "a3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedMatches []ntuple.Match

			// Custom FromPartial that captures the Match for inspection
			fromPartial := func(m ntuple.Match) (veles.Secret, bool) {
				capturedMatches = append(capturedMatches, m)
				return mockSecret{Value: string(m.Value)}, true
			}

			d := &ntuple.Detector{
				MaxElementLen: 10,
				MaxDistance:   5, // Small distance to prevent tuple formation
				Finders: []ntuple.Finder{
					ntuple.FindAllMatches(aPattern),
					ntuple.FindAllMatches(bPattern),
					ntuple.FindAllMatches(cPattern),
				},
				FromTuple:   mockSecretFromTuple,
				FromPartial: fromPartial,
			}

			_, _ = d.Detect([]byte(tt.input))

			// Verify we got the expected number of partial matches
			if len(capturedMatches) != len(tt.wantFinderIndexes) {
				t.Fatalf("Expected %d partial matches, got %d", len(tt.wantFinderIndexes), len(capturedMatches))
			}

			// Verify each match has the correct FinderIndex and Value
			for i, m := range capturedMatches {
				if m.FinderIndex != tt.wantFinderIndexes[i] {
					t.Errorf("Match %d: expected FinderIndex=%d, got FinderIndex=%d (value=%q)",
						i, tt.wantFinderIndexes[i], m.FinderIndex, string(m.Value))
				}
				if string(m.Value) != tt.wantValues[i] {
					t.Errorf("Match %d: expected Value=%q, got Value=%q",
						i, tt.wantValues[i], string(m.Value))
				}
			}
		})
	}
}

// TestFinderIndexSetForTuples verifies that FinderIndex is correctly set
// for matches that form complete tuples.
func TestFinderIndexSetForTuples(t *testing.T) {
	aPattern := regexp.MustCompile(`a[0-9]`)
	bPattern := regexp.MustCompile(`b[0-9]`)
	cPattern := regexp.MustCompile(`c[0-9]`)

	var capturedMatches []ntuple.Match

	// Custom FromTuple that captures the Matches for inspection
	fromTuple := func(ms []ntuple.Match) (veles.Secret, bool) {
		capturedMatches = append(capturedMatches, ms...)
		return mockSecretFromTuple(ms)
	}

	d := &ntuple.Detector{
		MaxElementLen: 10,
		MaxDistance:   1000,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatches(aPattern),
			ntuple.FindAllMatches(bPattern),
			ntuple.FindAllMatches(cPattern),
		},
		FromTuple: fromTuple,
	}

	input := "a1 b1 c1"
	_, _ = d.Detect([]byte(input))

	// Should have captured 3 matches (one from each finder)
	if len(capturedMatches) != 3 {
		t.Fatalf("Expected 3 matches in tuple, got %d", len(capturedMatches))
	}

	// Verify each match has the correct FinderIndex
	expectedIndexes := map[string]int{
		"a1": 0,
		"b1": 1,
		"c1": 2,
	}

	for _, m := range capturedMatches {
		value := string(m.Value)
		expectedIndex, ok := expectedIndexes[value]
		if !ok {
			t.Errorf("Unexpected match value: %q", value)
			continue
		}
		if m.FinderIndex != expectedIndex {
			t.Errorf("Match %q: expected FinderIndex=%d, got FinderIndex=%d",
				value, expectedIndex, m.FinderIndex)
		}
	}
}
