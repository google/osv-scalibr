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

package simpletoken_test

import (
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// TestDetect_truePositives tests for cases where we know Detect will return a
// match/matches.
func TestDetect_truePositives(t *testing.T) {
	cases := []struct {
		name         string
		regexp       string
		maxSecretLen uint32
		in           []byte
		want         []veles.Secret
		wantPos      []int
		fromMatch    func([]byte) (veles.Secret, bool)
	}{{
		name:         "match only",
		regexp:       "FOO",
		maxSecretLen: 3,
		in:           []byte("FOO"),
		want:         []veles.Secret{"FOO"},
		wantPos:      []int{0},
	}, {
		name:         "match at beginning",
		regexp:       "FOO",
		maxSecretLen: 3,
		in:           []byte("FOOa"),
		want:         []veles.Secret{"FOO"},
		wantPos:      []int{0},
	}, {
		name:         "match in middle",
		regexp:       "FOO",
		maxSecretLen: 3,
		in:           []byte("aFOOa"),
		want:         []veles.Secret{"FOO"},
		wantPos:      []int{1},
	}, {
		name:         "match at end",
		regexp:       "FOO",
		maxSecretLen: 3,
		in:           []byte("aFOO"),
		want:         []veles.Secret{"FOO"},
		wantPos:      []int{1},
	}, {
		name:         "match at end",
		regexp:       "FOO",
		maxSecretLen: 3,
		in:           []byte("aFOO"),
		want:         []veles.Secret{"FOO"},
		wantPos:      []int{1},
	}, {
		name:         "multiple matches",
		regexp:       "FOO",
		maxSecretLen: 3,
		in:           []byte("FOO FOO"), //nolint:dupword
		want:         []veles.Secret{"FOO", "FOO"},
		wantPos:      []int{0, 4},
	}, {
		name:         "multi-line input",
		regexp:       "FOO",
		maxSecretLen: 3,
		in: []byte(`
FOO
BAR
BAZ
		`),
		want:    []veles.Secret{"FOO"},
		wantPos: []int{1},
	}, {
		name:         "multiple distinct matches",
		regexp:       "[A-Z]{3}",
		maxSecretLen: 3,
		in:           []byte("FOO BAR"),
		want:         []veles.Secret{"FOO", "BAR"},
		wantPos:      []int{0, 4},
	}, {
		name:         "not ok",
		regexp:       "[A-Z]{3}",
		maxSecretLen: 3,
		in:           []byte("FOO BAR"),
		want:         []veles.Secret{"BAR"},
		wantPos:      []int{4},
		fromMatch: func(b []byte) (veles.Secret, bool) {
			if string(b) == "FOO" {
				return nil, false
			}
			return string(b), true
		},
	}, {
		// See https://pkg.go.dev/regexp and
		// https://github.com/google/re2/wiki/syntax.
		name:         "matches do not overlap",
		regexp:       "[A-Z]{3}",
		maxSecretLen: 3,
		in:           []byte("FOOBAR"),
		want:         []veles.Secret{"FOO", "BAR"},
		wantPos:      []int{0, 3},
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.fromMatch == nil {
				tc.fromMatch = func(b []byte) (veles.Secret, bool) {
					return string(b), true
				}
			}
			d := simpletoken.Detector{
				MaxLen:    tc.maxSecretLen,
				Re:        regexp.MustCompile(tc.regexp),
				FromMatch: tc.fromMatch,
			}
			got, gotPos := d.Detect(tc.in)
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantPos, gotPos, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDetect_trueNegative tests for cases where we know Detect will not return
// a match.
func TestDetect_trueNegatives(t *testing.T) {
	cases := []struct {
		name         string
		regexp       string
		maxSecretLen uint32
		in           []byte
		want         []veles.Secret
		wantPos      []int
	}{{
		name:         "no match",
		regexp:       "FOO",
		maxSecretLen: 3,
		in:           []byte("BAR"),
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := simpletoken.Detector{
				MaxLen: tc.maxSecretLen,
				Re:     regexp.MustCompile(tc.regexp),
				FromMatch: func(b []byte) (veles.Secret, bool) {
					return string(b), true
				},
			}
			got, gotPos := d.Detect(tc.in)
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantPos, gotPos, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
