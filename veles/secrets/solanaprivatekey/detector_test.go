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

package solanaprivatekey

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
			name:    "Solana key with keyword",
			content: "solana_private_key = \"4k3DyjSc5XvS6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6abcd\"",
			want: []veles.Secret{
				SolanaPrivateKey{Key: "4k3DyjSc5XvS6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6abcd"},
			},
		},
		{
			name:    "Solana key with phantom keyword",
			content: "phantom: 4k3DyjSc5XvS6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6abcd",
			want: []veles.Secret{
				SolanaPrivateKey{Key: "4k3DyjSc5XvS6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6abcd"},
			},
		},
		{
			name:    "No keyword",
			content: "4k3DyjSc5XvS6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6abcd",
			want:    nil,
		},
		{
			name:    "Invalid length",
			content: "solana: 4k3DyjScl5XvS6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6L6q6",
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
