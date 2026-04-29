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

package starknetprivatekey

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
			name:    "Starknet key with keyword",
			content: "starknet_private_key = \"0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"",
			want: []veles.Secret{
				StarknetPrivateKey{Key: "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
			},
		},
		{
			name:    "Starknet key with argent keyword",
			content: "argent: 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []veles.Secret{
				StarknetPrivateKey{Key: "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
			},
		},
		{
			name:    "No keyword",
			content: "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want:    nil,
		},
		{
			name:    "Invalid length",
			content: "starknet: 0x0123456789abcdef",
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
