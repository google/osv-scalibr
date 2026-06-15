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

package paypal_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/paypal"
	"github.com/google/osv-scalibr/veles/velestest"
)

var (
	// detectorClientID is a synthetic but well-formed PayPal Client ID:
	// starts with "A", exactly 80 URL-safe characters.
	detectorClientID = "A" + strings.Repeat("aBcDeFgHiJ", 7) + "aBcDeFgHi"
	// detectorClientSecret is a synthetic but well-formed PayPal Client Secret:
	// starts with "E", exactly 80 URL-safe characters.
	detectorClientSecret = "E" + strings.Repeat("KlMnOpQrSt", 7) + "KlMnOpQrS"
)

func TestMain(m *testing.M) {
	if len(detectorClientID) != 80 {
		panic("detectorClientID should be 80 chars")
	}
	if len(detectorClientSecret) != 80 {
		panic("detectorClientSecret should be 80 chars")
	}
	os.Exit(m.Run())
}

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		paypal.NewDetector(),
		fmt.Sprintf("%s\n%s", detectorClientID, detectorClientSecret),
		paypal.Credentials{ID: detectorClientID, Secret: detectorClientSecret},
	)
}

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{paypal.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
		{
			name:  "non-credential input",
			input: "Some random text without credentials",
			want:  nil,
		},
		{
			name:  "client ID only (no secret) is not reported",
			input: "paypal_client_id: " + detectorClientID,
			want:  nil,
		},
		{
			name:  "client secret only (no ID) is not reported",
			input: "paypal_client_secret: " + detectorClientSecret,
			want:  nil,
		},
		{
			name:  "client ID with wrong prefix is not matched",
			input: fmt.Sprintf("Z%s\n%s", detectorClientID[1:], detectorClientSecret),
			want:  nil,
		},
		{
			name:  "client secret with wrong prefix is not matched",
			input: fmt.Sprintf("%s\nZ%s", detectorClientID, detectorClientSecret[1:]),
			want:  nil,
		},
		{
			name:  "ID and secret in close proximity (happy path)",
			input: fmt.Sprintf("%s\n%s", detectorClientID, detectorClientSecret),
			want: []veles.Secret{
				paypal.Credentials{ID: detectorClientID, Secret: detectorClientSecret},
			},
		},
		{
			name: "ID and secret in JSON config",
			input: fmt.Sprintf(`{
  "client_id": "%s",
  "client_secret": "%s"
}`, detectorClientID, detectorClientSecret),
			want: []veles.Secret{
				paypal.Credentials{ID: detectorClientID, Secret: detectorClientSecret},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
