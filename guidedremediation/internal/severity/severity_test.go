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

package severity_test

import (
	"math"
	"testing"

	"github.com/google/osv-scalibr/guidedremediation/internal/severity"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestSeverity_CalculateScore(t *testing.T) {
	tests := []struct {
		name string
		sev  *osvpb.Severity
		want float64
	}{
		{
			name: "Empty Severity Type",
			sev:  &osvpb.Severity{},
			want: -1,
		},
		{
			name: "CVSS v2.0",
			sev: &osvpb.Severity{
				Type:  osvpb.Severity_CVSS_V2,
				Score: "AV:L/AC:M/Au:N/C:N/I:P/A:C/E:H/RL:U/RC:C/CDP:LM/TD:M/CR:L/IR:M/AR:H",
			},
			want: 5.4,
		},
		{
			name: "CVSS v3.0",
			sev: &osvpb.Severity{
				Type:  osvpb.Severity_CVSS_V3,
				Score: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H",
			},
			want: 10.0,
		},
		{
			name: "CVSS v3.1",
			sev: &osvpb.Severity{
				Type:  osvpb.Severity_CVSS_V3,
				Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H",
			},
			want: 10.0,
		},
		{
			name: "CVSS v4.0",
			sev: &osvpb.Severity{
				Type:  osvpb.Severity_CVSS_V4,
				Score: "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear",
			},
			want: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := severity.CalculateScore(tt.sev)
			if err != nil {
				t.Errorf("CalculateScore() error: %v", err)
			}
			// CVSS scores are only supposed to be to 1 decimal place.
			// Multiply and round to get around potential precision issues.
			if math.Round(10*got) != math.Round(10*tt.want) {
				t.Errorf("CalculateScore() = %.1f, want %.1f", got, tt.want)
			}
		})
	}
}
