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

package spdx_test

import (
	"testing"

	"bitbucket.org/creachadair/stringset"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/converter/spdx"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func TestLicenseExpression(t *testing.T) {
	tests := []struct {
		name              string
		licenses          []string
		wantExpr          string
		wantOtherLicenses stringset.Set
	}{
		{
			name:              "empty licenses list",
			licenses:          []string{},
			wantExpr:          spdx.NoAssertion,
			wantOtherLicenses: stringset.New(),
		},
		{
			name:              "just empty string licenses",
			licenses:          []string{"", "", ""},
			wantExpr:          spdx.NoAssertion,
			wantOtherLicenses: stringset.New(),
		},
		{
			name:              "has non-standard",
			licenses:          []string{"NON-STANDARD", "MIT"},
			wantExpr:          spdx.NoAssertion,
			wantOtherLicenses: stringset.New(),
		},
		{
			name:              "has unknown",
			licenses:          []string{"UNKNOWN", "MIT"},
			wantExpr:          spdx.NoAssertion,
			wantOtherLicenses: stringset.New(),
		},
		{
			name:              "MIT",
			licenses:          []string{"MIT"},
			wantExpr:          "MIT",
			wantOtherLicenses: stringset.New(),
		},
		{
			name:              "MIT in parens",
			licenses:          []string{"(MIT)"},
			wantExpr:          "MIT",
			wantOtherLicenses: stringset.New(),
		},
		{
			name:              "Multiple values",
			licenses:          []string{"MIT", "LGPL-2.0-only"},
			wantExpr:          "LGPL-2.0-only AND MIT",
			wantOtherLicenses: stringset.New(),
		},
		{
			name:              "OR value",
			licenses:          []string{"MIT OR LGPL-2.0-only"},
			wantExpr:          "(MIT OR LGPL-2.0-only)",
			wantOtherLicenses: stringset.New(),
		},
		{
			name:              "non-spdx license",
			licenses:          []string{"MADE UP"},
			wantExpr:          "LicenseRef-MADE-UP",
			wantOtherLicenses: stringset.New("MADE UP"),
		},
		{
			name:              "OR with non-spdx license",
			licenses:          []string{"MADE UP OR MIT"},
			wantExpr:          "(LicenseRef-MADE-UP OR MIT)",
			wantOtherLicenses: stringset.New("MADE UP"),
		},
		{
			name:              "Complicated expression",
			licenses:          []string{"MADE UP OR MIT", "(CC0-1.0 and AGPL-1.0-only)", "(MIT or LGPL-2.0-only)", "??", "CC0-1.0"},
			wantExpr:          "(LicenseRef-MADE-UP OR MIT) AND (MIT OR LGPL-2.0-only) AND AGPL-1.0-only AND CC0-1.0 AND LicenseRef---",
			wantOtherLicenses: stringset.New("MADE UP", "??"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotExpr, gotOtherLicenses := spdx.LicenseExpression(tc.licenses)
			if gotExpr != tc.wantExpr {
				t.Errorf("expr err - licenseExpression(%v) = %q, want %q", tc.licenses, gotExpr, tc.wantExpr)
			}
			if diff := cmp.Diff(tc.wantOtherLicenses, gotOtherLicenses, cmpopts.SortSlices(func(a, b *v2_3.OtherLicense) bool { return a.LicenseIdentifier < b.LicenseIdentifier })); diff != "" {
				t.Errorf("custom err - licenseExpression(%v) returned unexpected diff (-want +got):\n%s", tc.licenses, diff)
			}
		})
	}
}
