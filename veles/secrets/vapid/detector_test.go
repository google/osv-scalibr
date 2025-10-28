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

package vapid_test

import (
	"fmt"
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
			name:  "empty input",
			input: "",
			want:  nil,
		},
		{
			name: "correct syntax - bad key",
			input: `
				Not Vapid Private Key: LieO7JztGnRv11UxRNJlBkdoK97_PceW7rGXQh36c_4
				Vapid Public Key: BFEuu_r7cd5hElHB6P9Z1bysARpVxRljjRZEmlrfMTPT2G_GRTGrCOid4WCk4PAnyaFXLPa0sOLMnMMS1sMrMRs
			`,
			want: nil,
		},
		{
			name: "correct syntax - bad key - choose the right one",
			input: `
				Vapid Private Key: LieO7JztGnRv11UxRNJlBkdoK97ePceW7rGXQh36c_4
				Not Vapid Private Key: LieO7JztGnRv11UxRNJlBkdoK97_PceW7rGXQh36c_4
				Vapid Public Key: BFEuu_r7cd5hElHB6P9Z1bysARpVxRljjRZEmlrfMTPT2G_GRTGrCOid4WCk4PAnyaFXLPa0sOLMnMMS1sMrMRs
			`,
			want: []veles.Secret{
				vapid.Keys{
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
				vapid.Keys{
					PrivateB64: "LieO7JztGnRv11UxRNJlBkdoK97ePceW7rGXQh36c_4",
					PublicB64:  "BFEuu_r7cd5hElHB6P9Z1bysARpVxRljjRZEmlrfMTPT2G_GRTGrCOid4WCk4PAnyaFXLPa0sOLMnMMS1sMrMRs",
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
			fmt.Printf("got = %+v\n", got)
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
