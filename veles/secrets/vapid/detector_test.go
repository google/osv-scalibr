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

package vapid_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/vapid"
)

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{vapid.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		// --- Empty or invalid input ---
		{
			name:  "empty_input",
			input: "",
			want:  nil,
		},
		{
			name: "correct_syntax_-_bad_key",
			input: `
				Not Vapid Private Key: LieO7JztGnRv11UxRNJlBkdoK97_PceW7rGXQh36c_4
				Vapid Public Key: BFEuu_r7cd5hElHB6P9Z1bysARpVxRljjRZEmlrfMTPT2G_GRTGrCOid4WCk4PAnyaFXLPa0sOLMnMMS1sMrMRs
			`,
			want: nil,
		},
		{
			name: "correct_syntax_-_bad_key_-_choose_the_right one",
			input: `
				Vapid Private Key: LieO7JztGnRv11UxRNJlBkdoK97ePceW7rGXQh36c_4
				Not Vapid Private Key: LieO7JztGnRv11UxRNJlBkdoK97_PceW7rGXQh36c_4
				Vapid Public Key: BFEuu_r7cd5hElHB6P9Z1bysARpVxRljjRZEmlrfMTPT2G_GRTGrCOid4WCk4PAnyaFXLPa0sOLMnMMS1sMrMRs
			`,
			want: []veles.Secret{
				vapid.Key{
					PrivateB64: "LieO7JztGnRv11UxRNJlBkdoK97ePceW7rGXQh36c_4",
					PublicB64:  "BFEuu_r7cd5hElHB6P9Z1bysARpVxRljjRZEmlrfMTPT2G_GRTGrCOid4WCk4PAnyaFXLPa0sOLMnMMS1sMrMRs",
				},
			},
		},
		{
			name: "correct",
			input: `
				Vapid Private Key: LieO7JztGnRv11UxRNJlBkdoK97ePceW7rGXQh36c_4
				Vapid Public Key: BFEuu_r7cd5hElHB6P9Z1bysARpVxRljjRZEmlrfMTPT2G_GRTGrCOid4WCk4PAnyaFXLPa0sOLMnMMS1sMrMRs
			`,
			want: []veles.Secret{
				vapid.Key{
					PrivateB64: "LieO7JztGnRv11UxRNJlBkdoK97ePceW7rGXQh36c_4",
					PublicB64:  "BFEuu_r7cd5hElHB6P9Z1bysARpVxRljjRZEmlrfMTPT2G_GRTGrCOid4WCk4PAnyaFXLPa0sOLMnMMS1sMrMRs",
				},
			},
		},
		{
			name:  "correct_-_tuple",
			input: `LieO7JztGnRv11UxRNJlBkdoK97ePceW7rGXQh36c_4:BFEuu_r7cd5hElHB6P9Z1bysARpVxRljjRZEmlrfMTPT2G_GRTGrCOid4WCk4PAnyaFXLPa0sOLMnMMS1sMrMRs`,
			want: []veles.Secret{
				vapid.Key{
					PrivateB64: "LieO7JztGnRv11UxRNJlBkdoK97ePceW7rGXQh36c_4",
					PublicB64:  "BFEuu_r7cd5hElHB6P9Z1bysARpVxRljjRZEmlrfMTPT2G_GRTGrCOid4WCk4PAnyaFXLPa0sOLMnMMS1sMrMRs",
				},
			},
		},
		{
			name:  "only_public",
			input: `VapidPublicKey: BFEuu_r7cd5hElHB6P9Z1bysARpVxRljjRZEmlrfMTPT2G_GRTGrCOid4WCk4PAnyaFXLPa0sOLMnMMS1sMrMRs`,
			want:  nil,
		},
		{
			name:  "only_private_-_no_context",
			input: `Lu7AeLYdEUws2iLm97LcwAbQCI1YA8NpLEe485kmO5s`,
			want:  nil,
		},
		{
			name:  "only_private_-_context",
			input: `VapidPrivateKey: LieO7JztGnRv11UxRNJlBkdoK97ePceW7rGXQh36c_4`,
			want:  nil,
		},
		{
			name: "complex_multiline_-_private_key_omitted,_should_not_match",
			input: `
				VapidPrivateKey: ****
				VapidPublicKey: BE7cFYQ2l4kASZ_7iKwAy6L2hztWwTKrwd41SkRJuGyo6J5vR9ATeUufONHzoaseSpKtcJbm5xLTkmo--IWpEt8
			`,
			want: []veles.Secret{},
		},
		{
			name: "complex_multiline_-_no_multiline_context_match",
			input: `
				VapidPrivateKey:
				LieO7JztGnRv11UxRNJlBkdoK97ePceW7rGXQh36c_4
			`,
			want: []veles.Secret{},
		},
		{
			name: "complex_javascript_-_match",
			input: `
			function setup() {
			  webpush.setVapidDetails(
			    'mailto:email@email.com',
			    'BFKSGCtM-gouDaPSNYwDRmCTCSEelTpujQ6mHG2KIXaaJI9WLReodcS00QE4ck8P5uPHLSkNKZ7ZAWjpgITwrNI',
			    'rrvzfePgU7wc8RP7fcSMR-8ur2nDzqissXT5ovojK6Q'
			  );
			  return Promise.resolve();
			}
			`,
			want: []veles.Secret{
				vapid.Key{
					PrivateB64: "rrvzfePgU7wc8RP7fcSMR-8ur2nDzqissXT5ovojK6Q",
					PublicB64:  "BFKSGCtM-gouDaPSNYwDRmCTCSEelTpujQ6mHG2KIXaaJI9WLReodcS00QE4ck8P5uPHLSkNKZ7ZAWjpgITwrNI",
				},
			},
		},
		{
			name: "complex_golang_-_no_match",
			input: `
			resp, err := webpush.SendNotification([]byte("Test"), s, &webpush.Options{
				Subscriber:      "example@example.com", // Do not include "mailto:"
				VAPIDPublicKey:  vapidPublicKey,
				VAPIDPrivateKey: vapidPrivateKey,
				TTL:             30,
			})
			`,
			want: []veles.Secret{},
		},
		{
			name: "complex_golang_-_match",
			input: `
			resp, err := webpush.SendNotification([]byte("Test"), s, &webpush.Options{
				Subscriber:      "example@example.com", // Do not include "mailto:"
				VAPIDPublicKey:  "rrvzfePgU7wc8RP7fcSMR-8ur2nDzqissXT5ovojK6Q",
				VAPIDPrivateKey: "BFKSGCtM-gouDaPSNYwDRmCTCSEelTpujQ6mHG2KIXaaJI9WLReodcS00QE4ck8P5uPHLSkNKZ7ZAWjpgITwrNI",
				TTL:             30,
			})
			`,
			want: []veles.Secret{
				vapid.Key{
					PrivateB64: "rrvzfePgU7wc8RP7fcSMR-8ur2nDzqissXT5ovojK6Q",
					PublicB64:  "BFKSGCtM-gouDaPSNYwDRmCTCSEelTpujQ6mHG2KIXaaJI9WLReodcS00QE4ck8P5uPHLSkNKZ7ZAWjpgITwrNI",
				},
			},
		},
		{
			name: "json_match",
			input: `
		 "webPush": {
        "subject": "http://example.com",
        "vapidPublicKey": "BKC9CAak3PFu0nhmVbEFs0HG0o6T1bMb-q_iSAtiYHv2zdQM_IPkz1A9gzVd_-4cNYMeLwq1i8gA83-U0pc4aOk",
        "vapidPrivateKey": "CSOfcDX5bADZupzLZFoIwvqfyPMEz-vZtJORwHTLPR0"
      },
			`,
			want: []veles.Secret{
				vapid.Key{
					PrivateB64: "CSOfcDX5bADZupzLZFoIwvqfyPMEz-vZtJORwHTLPR0",
					PublicB64:  "BKC9CAak3PFu0nhmVbEFs0HG0o6T1bMb-q_iSAtiYHv2zdQM_IPkz1A9gzVd_-4cNYMeLwq1i8gA83-U0pc4aOk",
				},
			},
		},
		{
			name: "json_match_-_context_only",
			input: `
		 "webPush": {
        "subject": "http://example.com",
        "vapidPrivateKey": "CSOfcDX5bADZupzLZFoIwvqfyPMEz-vZtJORwHTLPR0"
      },
			`,
			want: nil,
		},
		{
			name: "json_match_-_no_context",
			input: `
		  {
			  "Vapid": {
			    "Subject": "mailto:email@outlook.com",
			    "PublicKey": "BEEDPFMgrB5MObgTsdiIh9fQ9Ug5wrLQyk4sDxSYctvqEzFHa9wLGE0-ZDs0A8jXzJHsFVSXshYzDDoLw2YxWGw",
			    "PrivateKey": "gIe4zn7y8cgAyxLVk-6NX_mpR-1R_aPx_8CZ1VI0oYg"
			  },
				...
			}
			`,
			want: []veles.Secret{
				vapid.Key{
					PrivateB64: "gIe4zn7y8cgAyxLVk-6NX_mpR-1R_aPx_8CZ1VI0oYg",
					PublicB64:  "BEEDPFMgrB5MObgTsdiIh9fQ9Ug5wrLQyk4sDxSYctvqEzFHa9wLGE0-ZDs0A8jXzJHsFVSXshYzDDoLw2YxWGw",
				},
			},
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
