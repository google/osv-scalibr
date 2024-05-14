// Copyright 2024 Google LLC
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

package internal

import (
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMatchCaptureGroups(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		pattern  string
		want map[string]string
	}{
		{
			name:    "go-case",
			input:   "match this thing",
			pattern: `(?P<name>match).*(?P<version>thing)`,
			want: map[string]string{
				"name":    "match",
				"version": "thing",
			},
		},
		{
			name:    "only matches the first instance",
			input:   "match this thing batch another think",
			pattern: `(?P<name>[mb]atch).*?(?P<version>thin[gk])`,
			want: map[string]string{
				"name":    "match",
				"version": "thing",
			},
		},
		{
			name:    "nested capture groups",
			input:   "cool something to match against",
			pattern: `((?P<name>match) (?P<version>against))`,
			want: map[string]string{
				"name":    "match",
				"version": "against",
			},
		},
		{
			name:    "nested optional capture groups",
			input:   "cool something to match against",
			pattern: `((?P<name>match) (?P<version>against))?`,
			want: map[string]string{
				"name":    "match",
				"version": "against",
			},
		},
		{
			name:    "nested optional capture groups with larger match",
			input:   "cool something to match against match never",
			pattern: `.*?((?P<name>match) (?P<version>(against|never)))?`,
			want: map[string]string{
				"name":    "match",
				"version": "against",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := MatchNamedCaptureGroups(regexp.MustCompile(test.pattern), test.input)
			if !cmp.Equal(test.want, got) {
				t.Errorf("MatchNamedCaptureGroups(%q) = %v, want %v", test.pattern, got, test.want)
			}
		})
	}
}
