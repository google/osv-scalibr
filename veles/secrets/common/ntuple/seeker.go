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

// seeker is used to iterate over a set of matches in a multi-pointer manner
type seeker struct {
	Index   int
	Matches []Match
}

// Start returns the start position of a seeker
func (s *seeker) Start() int {
	return s.Matches[s.Index].Start
}

// Seek makes the seeker go to the next match
func (s *seeker) Seek() {
	s.Index++
}

// EOM returns true if the seeker has arrived to the end of matches
func (s *seeker) EOM() bool {
	return s.Index == len(s.Matches)-1
}
