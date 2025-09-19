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

package github_test

import (
	"testing"

	"github.com/google/osv-scalibr/veles/secrets/github"
)

func TestValidateChecksum(t *testing.T) {
	testcases := []struct {
		name  string
		token string
		want  bool
	}{
		{
			name:  "example valid",
			token: `ghr_OWOCPzqKuy3J4w53QpkLfffjBUJSh5yLnFHj7wiyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG8fw`,
			want:  true,
		},
		{
			name:  "another example valid",
			token: `ghu_aGgfQsQ52sImE9zwWxKcjt2nhESfYG1U2FhX`,
			want:  true,
		},
		{
			name:  "invalid token",
			token: `fjneiwnfewkfew`,
			want:  false,
		},
		{
			name:  "invalid checksum",
			token: `ghr_OWOCPzqKuy3J4w53QpkLfffjBUJSh5yLnFHj7wiyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG1fw`,
			want:  false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := github.ValidateChecksum([]byte(tc.token))
			if got != tc.want {
				t.Errorf("ValidateChecksum() = %t, want %t", got, tc.want)
			}
		})
	}
}
