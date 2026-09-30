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

package geminiagentidentity

import (
	"reflect"
	"testing"

	"github.com/google/osv-scalibr/veles"
)

func TestDetector(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []veles.Secret
	}{
		{
			name:    "Valid Agent Identity",
			content: "agent_id = 'principal://agents.global.google.com/projects/test-project/locations/us-central1/agents/my-agent'",
			want: []veles.Secret{
				GeminiAgentIdentity{Identity: "principal://agents.global.google.com/projects/test-project/locations/us-central1/agents/my-agent"},
			},
		},
		{
			name:    "Invalid path",
			content: "principal://agents.global.google.com/locations/us-central1/agents/my-agent",
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDetector()
			got, _ := d.Detect([]byte(tt.content))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Detect() = %v, want %v", got, tt.want)
			}
		})
	}
}
