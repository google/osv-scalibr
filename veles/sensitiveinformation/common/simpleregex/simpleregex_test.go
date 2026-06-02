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

package simpleregex

import (
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
)

func fakeSensitiveInformation(b []byte) sensitiveinformation.SensitiveInformation {
	return sensitiveinformation.SensitiveInformation{
		Raw: b,
	}
}

// TestDetect_truePositives tests for cases where we know Detect will return a
// match/matches.
func TestDetect_truePositives(t *testing.T) {
	cases := []struct {
		name      string
		regexp    string
		maxLen    uint32
		before    uint32
		after     uint32
		keywords  []string
		in        []byte
		want      []veles.Secret
		wantPos   []int
		fromMatch func([]byte) (sensitiveinformation.SensitiveInformation, bool)
	}{
		{
			name:   "match only",
			regexp: "FOO",
			maxLen: 3,
			in:     []byte("FOO"),
			want: []veles.Secret{
				fakeSensitiveInformation([]byte("FOO")),
			},
			wantPos: []int{0},
		}, {
			name:   "match at beginning",
			regexp: "FOO",
			maxLen: 3,
			in:     []byte("FOOa"),
			want: []veles.Secret{
				fakeSensitiveInformation([]byte("FOO")),
			},
			wantPos: []int{0},
		}, {
			name:   "match in middle",
			regexp: "FOO",
			maxLen: 3,
			in:     []byte("aFOOa"),
			want: []veles.Secret{
				fakeSensitiveInformation([]byte("FOO")),
			},
			wantPos: []int{1},
		}, {
			name:   "match at end",
			regexp: "FOO",
			maxLen: 3,
			in:     []byte("aFOO"),
			want: []veles.Secret{
				fakeSensitiveInformation([]byte("FOO")),
			},
			wantPos: []int{1},
		}, {
			name:   "multiple matches",
			regexp: "FOO",
			maxLen: 3,
			in:     []byte("FOO FOO"), //nolint:dupword
			want: []veles.Secret{
				fakeSensitiveInformation([]byte("FOO")),
				fakeSensitiveInformation([]byte("FOO")),
			},
			wantPos: []int{0, 4},
		}, {
			name:   "multi-line input",
			regexp: "FOO",
			maxLen: 3,
			in: []byte(`
FOO
BAR
BAZ
		`),
			want: []veles.Secret{
				fakeSensitiveInformation([]byte("FOO")),
			},
			wantPos: []int{1},
		}, {
			name:   "multiple distinct matches",
			regexp: "[A-Z]{3}",
			maxLen: 3,
			in:     []byte("FOO BAR"),
			want: []veles.Secret{
				fakeSensitiveInformation([]byte("FOO")),
				fakeSensitiveInformation([]byte("BAR")),
			},
			wantPos: []int{0, 4},
		}, {
			name:   "not ok",
			regexp: "[A-Z]{3}",
			maxLen: 3,
			in:     []byte("FOO BAR"),
			want: []veles.Secret{
				fakeSensitiveInformation([]byte("BAR")),
			},
			wantPos: []int{4},
			fromMatch: func(b []byte) (sensitiveinformation.SensitiveInformation, bool) {
				if string(b) == "FOO" {
					return sensitiveinformation.SensitiveInformation{}, false
				}
				return fakeSensitiveInformation(b), true
			},
		}, {
			// See https://pkg.go.dev/regexp and
			// https://github.com/google/re2/wiki/syntax.
			name:   "matches do not overlap",
			regexp: "[A-Z]{3}",
			maxLen: 3,
			in:     []byte("FOOBAR"),
			want: []veles.Secret{
				fakeSensitiveInformation([]byte("FOO")),
				fakeSensitiveInformation([]byte("BAR")),
			},
			wantPos: []int{0, 3},
		}, {
			name:     "keywords before",
			regexp:   "[A-Z]{3}",
			maxLen:   3,
			in:       []byte("FOO aBc BAR"),
			before:   4,
			keywords: []string{"abc", "def"},
			want: []veles.Secret{
				fakeSensitiveInformation([]byte("BAR")),
			},
			wantPos: []int{8},
		}, {
			name:     "keywords after",
			regexp:   "[A-Z]{3}",
			maxLen:   3,
			in:       []byte("FOO DEF BAR"),
			after:    4,
			keywords: []string{"abc", "def"},
			want: []veles.Secret{
				fakeSensitiveInformation([]byte("FOO")),
			},
			wantPos: []int{0},
		}, {
			name:     "keywords before and after",
			regexp:   "[A-Z]{3}",
			maxLen:   3,
			in:       []byte("ABC FOO DEF BAR ABC"),
			before:   4,
			after:    4,
			keywords: []string{"abc", "def"},
			want: []veles.Secret{
				fakeSensitiveInformation([]byte("FOO")),
				fakeSensitiveInformation([]byte("BAR")),
			},
			wantPos: []int{4, 12},
		}, {
			name:     "keywords matches regex",
			regexp:   "[A-Z]{3}",
			maxLen:   3,
			in:       []byte("ABC DEF ABC"),
			before:   4,
			keywords: []string{"abc", "def"},
			want: []veles.Secret{
				fakeSensitiveInformation([]byte("DEF")),
				fakeSensitiveInformation([]byte("ABC")),
			},
			wantPos: []int{4, 8},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.fromMatch == nil {
				tc.fromMatch = func(b []byte) (sensitiveinformation.SensitiveInformation, bool) {
					return fakeSensitiveInformation(b), true
				}
			}
			d := Detector{
				maxLen:              tc.maxLen,
				re:                  regexp.MustCompile(tc.regexp),
				contextWindowBefore: tc.before,
				contextWindowAfter:  tc.after,
				keywordsRe:          KeywordsRe(tc.keywords),
				fromMatch:           tc.fromMatch,
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
		name     string
		regexp   string
		maxLen   uint32
		before   uint32
		after    uint32
		keywords []string
		in       []byte
		want     []veles.Secret
		wantPos  []int
	}{{
		name:   "no match",
		regexp: "FOO",
		maxLen: 3,
		in:     []byte("BAR"),
	}, {
		name:     "no keyword match",
		regexp:   "FOO",
		keywords: []string{"abc", "def"},
		before:   4,
		after:    4,
		maxLen:   3,
		in:       []byte("FOO"),
	}, {
		name:     "keyword ahead of context window",
		regexp:   "FOO",
		keywords: []string{"abc", "def"},
		before:   3,
		after:    3,
		maxLen:   3,
		in:       []byte("abc FOO def"),
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fromMatch := func(b []byte) (sensitiveinformation.SensitiveInformation, bool) {
				return fakeSensitiveInformation(b), true
			}
			d := Detector{
				maxLen:              tc.maxLen,
				re:                  regexp.MustCompile(tc.regexp),
				contextWindowBefore: tc.before,
				contextWindowAfter:  tc.after,
				keywordsRe:          KeywordsRe(tc.keywords),
				fromMatch:           fromMatch,
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
