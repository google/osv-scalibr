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

import (
	"fmt"
)

// Match describes a single regex match for one element of a tuple.
// Start and End indicate absolute byte offsets into the input buffer, and
// Value holds the matched bytes.
// FinderIndex identifies which Finder produced this match.
type Match struct {
	Start       int
	End         int
	Value       []byte
	FinderIndex int
}

// String returns a readable representation of a single regex match.
func (m Match) String() string {
	// Truncate value if it's too long for a single log line
	val := string(m.Value)
	if len(val) > 32 {
		val = val[:29] + "..."
	}
	return fmt.Sprintf("[%d:%d](Idx:%d) %q", m.Start, m.End, m.FinderIndex, val)
}

func (m Match) overlaps(other Match) bool {
	return m.Start < other.End && other.Start < m.End
}

// Tuple represents a completed grouping of individual matches that together
// satisfy tuple constraints. A Tuple includes:
//   - Matches: the ordered list of element matches
//   - Start:   the minimum starting position among all matched elements
//   - End:     the maximum starting position among all elements (not End index)
//   - Dist:    the tuple distance metric = sum of gaps between secrets
type Tuple struct {
	Matches []Match
	Start   int
	End     int
	Dist    int
}
