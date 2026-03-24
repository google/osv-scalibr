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

package velestest_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles/velestest"
)

func TestFakeDetector(t *testing.T) {
	d := velestest.NewFakeDetector("FOO")
	cases := []struct {
		name          string
		input         string
		wantPositions []int
	}{
		{
			name:          "empty input",
			input:         "",
			wantPositions: nil,
		},
		{
			name:          "no match",
			input:         "afjsdfjadlsk;fjasd;kfj;lkaeruyaeiru32489304jlkadsf;348730940347",
			wantPositions: nil,
		},
		{
			name:          "match at start",
			input:         "FOOaaaaaaaaaaaaaaaaaaaa",
			wantPositions: []int{0},
		},
		{
			name:          "match at end",
			input:         "aaaaaaaaFOO",
			wantPositions: []int{8},
		},
		{
			name:          "match in middle",
			input:         "aaaaFOOaaaa",
			wantPositions: []int{4},
		},
		{
			name:          "multiple matches",
			input:         "aFOOaaaFOOaaa",
			wantPositions: []int{1, 7},
		},
		{
			name:          "case sensitive",
			input:         "aaafooaaa",
			wantPositions: nil,
		},
		{
			name:          "specific",
			input:         "FFFFOOOOOO",
			wantPositions: []int{3},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotSecrets, gotPositions := d.Detect([]byte(tc.input))
			if len(gotSecrets) != len(tc.wantPositions) {
				t.Errorf("Detect() len(secrets)=%d, want %d", len(gotSecrets), len(tc.wantPositions))
			}
			if diff := cmp.Diff(tc.wantPositions, gotPositions, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() positions diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFakeDetector_returnsHotword(t *testing.T) {
	d := velestest.NewFakeDetector("bar")
	secrets, _ := d.Detect([]byte("abara"))
	if secrets[0] != velestest.NewFakeStringSecret("bar") {
		t.Errorf("Detect() secret=%v, want FakeStringSecret(bar)", secrets[0])
	}
}
