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
	"strings"
)

// Match describes a single regex match for one element of a tuple.
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

// Tuple represents a completed grouping of individual matches.
type Tuple struct {
	Matches []Match
	Start   int
	End     int
	Dist    int
}

// String returns a detailed view of the tuple, its component matches, and its total internal gap.
func (t *Tuple) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Tuple[%d:%d] (Total Gap: %d):\n", t.Start, t.End, t.Dist))

	for i, m := range t.Matches {
		sb.WriteString(fmt.Sprintf("  %d: %s", i, m.String()))
		if i < len(t.Matches)-1 {
			sb.WriteString("\n")
		}
	}
	return sb.String()
}
