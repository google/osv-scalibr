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

package groupid_test

import (
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem/language/java/groupid"
)

func TestFromArtifactID(t *testing.T) {

	tests := []struct {
		name       string
		artifactID string
		want       string
	}{
		{
			name:       "No groupd ID found",
			artifactID: "some-artifact",
			want:       "",
		},
		{
			name:       "Group ID found",
			artifactID: "spring-web",
			want:       "org.springframework",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := groupid.FromArtifactID(tt.artifactID)
			if got != tt.want {
				t.Errorf("FromArtifactID(%s): got %s, want %s", tt.artifactID, got, tt.want)
			}
		})
	}
}
