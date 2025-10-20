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

package pair_test

import (
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

type mockSecret struct {
	Value string
}

// mock function to convert Pair to veles.Secret
func mockFromPair(p pair.Pair) (veles.Secret, bool) {
	return mockSecret{
		Value: p.A.Value + "-" + p.B.Value,
	}, true
}

func simpleFinder(t *testing.T, key string) func(data []byte) []*pair.Match {
	t.Helper()

	re := regexp.MustCompile(key + "[1-9]")
	return func(data []byte) []*pair.Match {
		var matches []*pair.Match
		for _, m := range re.FindAllSubmatchIndex(data, -1) {
			matches = append(matches, &pair.Match{
				Value:    string(data[m[0]:m[1]]),
				Position: m[0],
			})
		}
		return matches
	}
}

func TestFindOptimalPairs(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantSecrets []veles.Secret
		wantPos     []int
	}{
		{
			name:  "simple match",
			input: "a1 b1",
			wantSecrets: []veles.Secret{
				mockSecret{Value: "a1-b1"},
			},
			wantPos: []int{0},
		},
		{
			name:  "multiple matches, greedy selection",
			input: "a1 b1 a2 b2",
			wantSecrets: []veles.Secret{
				mockSecret{Value: "a1-b1"},
				mockSecret{Value: "a2-b2"},
			},
			wantPos: []int{0, 6},
		},
		{
			name:  "no matches",
			input: "a1 xxxxx",
		},
		{
			name:  "more bs than as",
			input: "a1 b1 b2",
			wantSecrets: []veles.Secret{
				mockSecret{Value: "a1-b1"},
			},
			wantPos: []int{0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &pair.Detector{
				// include the whole payload
				MaxLen:   uint32(len(tt.input)),
				FindA:    simpleFinder(t, "a"),
				FindB:    simpleFinder(t, "b"),
				FromPair: mockFromPair,
			}

			gotSecrets, gotPos := d.Detect([]byte(tt.input))
			if diff := cmp.Diff(tt.wantSecrets, gotSecrets); diff != "" {
				t.Errorf("Secrets mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantPos, gotPos); diff != "" {
				t.Errorf("Positions mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
