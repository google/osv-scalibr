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

package telegrambotapitoken_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/telegrambotapitoken"
)

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{telegrambotapitoken.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "empty_input",
			input: "",
			want:  nil,
		},
		{
			name:  "invalid_token_format_wrong_prefix",
			input: "tgram://483957481A:AAFD39kkdpWt3ywyRZergyOLMaJhac60qcE",
			want:  nil,
		},
		{
			name:  "invalid_token_format_too_short",
			input: "tgram://839574812:AAFD39kkdpWt3ywyRZergyOLMaJhac6",
			want:  nil,
		},
		{
			name:  "tgram_keyword_but_no_secret",
			input: `tgram://IKA1984R439T439HTH4`,
			want:  nil,
		},
		{
			name:  "false_positive_token_but_no_keyword",
			input: `falsealarm: 4839574812:AAFD39kkdpWt3ywyRZergyOLMaJhac60qcR`,
			want:  nil,
		},
		{
			name:  "valid_bot_token_with_tgram_keyword",
			input: `tgram://4839574812:AAFD39kkdpWt3ywyRZergyOLMaJhac60qcE`,
			want: []veles.Secret{
				telegrambotapitoken.TelegramBotAPIToken{
					Token: "4839574812:AAFD39kkdpWt3ywyRZergyOLMaJhac60qcE",
				},
			},
		},
		{
			name:  "valid_bot_token_with_Telegram_keyword",
			input: `Telegram key: 4839574812:AAFD39kkdpWt3ywyRZergyOLMaJhac60qcF`,
			want: []veles.Secret{
				telegrambotapitoken.TelegramBotAPIToken{
					Token: "4839574812:AAFD39kkdpWt3ywyRZergyOLMaJhac60qcF",
				},
			},
		},
		{
			name: "far_apart_token",
			input: `telegram:
AAAAAAAAAA` + strings.Repeat("\nfiller line with random data", 500) + `
4839574812:AAFD39kkdpWt3ywyRZergyOLMaJhac60qc`,
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
