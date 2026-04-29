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

package bip39mnemonic

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
			name:    "12-word mnemonic with keyword",
			content: "mnemonic: apple banana cherry dog elephant fish grape hat ice juice king lion",
			want: []veles.Secret{
				BIP39Mnemonic{Phrase: "apple banana cherry dog elephant fish grape hat ice juice king lion"},
			},
		},
		{
			name:    "24-word mnemonic with seed phrase keyword",
			content: "BIP39: apple banana cherry dog elephant fish grape hat ice juice king lion mouse north ocean paper quiet river stone tiger unit valve window xray",
			want: []veles.Secret{
				BIP39Mnemonic{Phrase: "apple banana cherry dog elephant fish grape hat ice juice king lion mouse north ocean paper quiet river stone tiger unit valve window xray"},
			},
		},
		{
			name:    "No keyword",
			content: "apple banana cherry dog elephant fish grape hat ice juice king lion",
			want:    nil,
		},
		{
			name:    "13-word mnemonic with keyword",
			content: "wallet: apple banana cherry dog elephant fish grape hat ice juice king lion mouse",
			want: []veles.Secret{
				BIP39Mnemonic{Phrase: "apple banana cherry dog elephant fish grape hat ice juice king lion mouse"},
			},
		},
		{
			name:    "Too few words",
			content: "mnemonic: apple banana cherry",
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
