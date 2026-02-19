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

package ntuple

// Match describes a single regex match for one element of a tuple.
type Match struct {
	Start       int
	End         int
	Value       []byte
	FinderIndex int
}

func (m Match) overlaps(other Match) bool {
	return m.Start < other.End && other.Start < m.End
}

// Tuple represents a completed grouping of individual matches.
type Tuple struct {
	Matches []Match
	Start   int
	End     int
	Dist    int
}

func (t *Tuple) overlaps(other *Tuple) bool {
	for _, mA := range t.Matches {
		for _, mB := range other.Matches {
			if mA.Start < mB.End && mB.Start < mA.End {
				return true
			}
		}
	}
	return false
}
