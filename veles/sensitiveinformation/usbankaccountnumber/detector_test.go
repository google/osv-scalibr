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

package usbankaccountnumber

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	validUsBankAccountNumberLen8  = "12345678"
	validUsBankAccountNumberLen9  = "123456789"
	validUsBankAccountNumberLen10 = "1234567890"
	validUsBankAccountNumberLen11 = "12345678901"
	validUsBankAccountNumberLen12 = "123456789012"
	validUsBankAccountNumberLen13 = "1234567890123"
	validUsBankAccountNumberLen14 = "12345678901234"
	validUsBankAccountNumberLen15 = "123456789012345"
	validUsBankAccountNumberLen16 = "1234567890123456"
	validUsBankAccountNumberLen17 = "12345678901234567"
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		NewDetector(),
		validUsBankAccountNumberLen9,
		buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodUnlikely),
	)
}

func TestDetector_Unlikely(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "account_no_keyword_len_8",
			input: `12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen8), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "account_no_keyword_len_9",
			input: `123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "account_no_keyword_len_10",
			input: `1234567890`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen10), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "account_no_keyword_len_11",
			input: `12345678901`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen11), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "account_no_keyword_len_12",
			input: `123456789012`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen12), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "account_no_keyword_len_13",
			input: `1234567890123`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen13), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "account_no_keyword_len_14",
			input: `12345678901234`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen14), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "account_no_keyword_len_15",
			input: `123456789012345`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen15), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "account_no_keyword_len_16",
			input: `1234567890123456`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen16), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "account_no_keyword_len_17",
			input: `12345678901234567`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen17), sensitiveinformation.LikelihoodUnlikely)},
		},
		{
			name:  "multiple_account_numbers",
			input: `12345678 123456789012`,
			want: []veles.Secret{
				buildExpectedResult([]byte(validUsBankAccountNumberLen8), sensitiveinformation.LikelihoodUnlikely),
				buildExpectedResult([]byte(validUsBankAccountNumberLen12), sensitiveinformation.LikelihoodUnlikely),
			},
		},
	}

	for _, tc := range cases {
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

func TestDetector_Likely(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "keyword_bank_before",
			input: `Bank: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_bank_after",
			input: `123456789 Bank`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_bank_lowercase",
			input: `bank: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_bank_uppercase",
			input: `BANK: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_bank_camelcase",
			input: `customerBank: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_bank_camelcase_number",
			input: `bankNumber: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_bank_snakecase",
			input: `customer_bank=123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_bank_snakecase_middle",
			input: `customer_bank_number=123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_bank_snakecase_uppercase",
			input: `CUSTOMER_BANK_NUMBER=123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_bank_json_key",
			input: `{"bank": "123456789"}`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_bank_parentheses",
			input: `(Bank) 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_account_before",
			input: `Account: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_account_after",
			input: `123456789 Account`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_account_lowercase",
			input: `account: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_account_uppercase",
			input: `ACCOUNT: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_account_camelcase",
			input: `checkingAccount: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_account_camelcase_number",
			input: `accountNumber: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_account_snakecase",
			input: `checking_account=123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_account_snakecase_middle",
			input: `checking_account_number=123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_account_snakecase_uppercase",
			input: `CHECKING_ACCOUNT_NUMBER=123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_account_json_key",
			input: `{"account": "123456789"}`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_account_parentheses",
			input: `(Account) 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_account_len_8",
			input: `Account: 12345678`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen8), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_account_len_17",
			input: `Account: 12345678901234567`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen17), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_us_before",
			input: `Us: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_us_after",
			input: `123456789 Us`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_us_lowercase",
			input: `us: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_us_uppercase",
			input: `US: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_us_json_key",
			input: `{"us": "123456789"}`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_us_parentheses",
			input: `(US) 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_jpmorgan_chase_titlecase",
			input: `JPMorgan Chase: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_jpmorgan_chase_lowercase",
			input: `jpmorgan chase: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_jpmorgan_chase_uppercase",
			input: `JPMORGAN CHASE: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_jpmorgan_chase_no_space",
			input: `JPMorganChase: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_jpmorgan_chase_hyphen",
			input: `JPMorgan-Chase: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_jpmorgan_chase_underscore",
			input: `jpmorgan_chase: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_jpmorgan_chase_after",
			input: `123456789 JPMorgan Chase`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_jpmorgan_chase_json_key",
			input: `{"jpmorgan_chase": "123456789"}`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_jpmorgan_chase_parentheses",
			input: `(JPMorgan Chase) 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_jpmorgan_only",
			input: `JPMorgan: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_chase_only",
			input: `Chase: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_jp_morgan_space",
			input: `JP Morgan: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_j_p_morgan_dots",
			input: `J.P. Morgan: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_bofa_titlecase",
			input: `BofA: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_bofa_lowercase",
			input: `bofa: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_bofa_uppercase",
			input: `BOFA: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_bofa_after",
			input: `123456789 BofA`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_bofa_json_key",
			input: `{"bofa": "123456789"}`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_bofa_parentheses",
			input: `(BofA) 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_wells_fargo_titlecase",
			input: `Wells Fargo: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_wells_fargo_lowercase",
			input: `wells fargo: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_wells_fargo_uppercase",
			input: `WELLS FARGO: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_wells_fargo_no_space",
			input: `WellsFargo: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_wells_fargo_hyphen",
			input: `Wells-Fargo: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_wells_fargo_underscore",
			input: `wells_fargo: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_wells_fargo_after",
			input: `123456789 Wells Fargo`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_wells_fargo_json_key",
			input: `{"wells_fargo": "123456789"}`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_wells_fargo_parentheses",
			input: `(Wells Fargo) 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_capital_one_titlecase",
			input: `Capital One: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_capital_one_lowercase",
			input: `capital one: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_capital_one_uppercase",
			input: `CAPITAL ONE: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_capital_one_no_space",
			input: `CapitalOne: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_capital_one_hyphen",
			input: `Capital-One: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_capital_one_underscore",
			input: `capital_one: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_capital_one_after",
			input: `123456789 Capital One`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_capital_one_json_key",
			input: `{"capital_one": "123456789"}`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_capital_one_parentheses",
			input: `(Capital One) 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_goldman_sachs_titlecase",
			input: `Goldman Sachs: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_goldman_sachs_lowercase",
			input: `goldman sachs: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_goldman_sachs_uppercase",
			input: `GOLDMAN SACHS: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_goldman_sachs_no_space",
			input: `GoldmanSachs: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_goldman_sachs_hyphen",
			input: `Goldman-Sachs: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_goldman_sachs_underscore",
			input: `goldman_sachs: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_goldman_sachs_after",
			input: `123456789 Goldman Sachs`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_goldman_sachs_json_key",
			input: `{"goldman_sachs": "123456789"}`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_goldman_sachs_parentheses",
			input: `(Goldman Sachs) 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_morgan_stanley_titlecase",
			input: `Morgan Stanley: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_morgan_stanley_lowercase",
			input: `morgan stanley: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_morgan_stanley_uppercase",
			input: `MORGAN STANLEY: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_morgan_stanley_no_space",
			input: `MorganStanley: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_morgan_stanley_hyphen",
			input: `Morgan-Stanley: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_morgan_stanley_underscore",
			input: `morgan_stanley: 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_morgan_stanley_after",
			input: `123456789 Morgan Stanley`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_morgan_stanley_json_key",
			input: `{"morgan_stanley": "123456789"}`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "keyword_morgan_stanley_parentheses",
			input: `(Morgan Stanley) 123456789`,
			want:  []veles.Secret{buildExpectedResult([]byte(validUsBankAccountNumberLen9), sensitiveinformation.LikelihoodLikely)},
		},
		{
			name:  "multiple_account_numbers",
			input: `Account: 12345678 123456789012`,
			want: []veles.Secret{
				buildExpectedResult([]byte(validUsBankAccountNumberLen8), sensitiveinformation.LikelihoodLikely),
				buildExpectedResult([]byte(validUsBankAccountNumberLen12), sensitiveinformation.LikelihoodLikely),
			},
		},
	}

	for _, tc := range cases {
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

func TestDetector_NoMatch(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "account_len_4",
			input: `Account: 1234`,
		},
		{
			name:  "account_len_5",
			input: `Account: 12345`,
		},
		{
			name:  "account_len_6",
			input: `Account: 123456`,
		},
		{
			name:  "account_len_7",
			input: `Account: 1234567`,
		},
		{
			name:  "alphanumeric_account_len_8_letter_start",
			input: `Account: a2345678`,
		},
		{
			name:  "alphanumeric_account_len_8_letter_middle",
			input: `Account: 1234a678`,
		},
		{
			name:  "alphanumeric_account_len_8_letter_end",
			input: `Account: 1234567a`,
		},
		{
			name:  "alphanumeric_account_len_9_letter_start",
			input: `Account: a23456789`,
		},
		{
			name:  "alphanumeric_account_len_9_letter_middle",
			input: `Account: 1234a6789`,
		},
		{
			name:  "alphanumeric_account_len_9_letter_end",
			input: `Account: 12345678a`,
		},
		{
			name:  "alphanumeric_account_len_10_letter_start",
			input: `Account: a234567890`,
		},
		{
			name:  "alphanumeric_account_len_10_letter_middle",
			input: `Account: 12345a7890`,
		},
		{
			name:  "alphanumeric_account_len_10_letter_end",
			input: `Account: 123456789a`,
		},
		{
			name:  "alphanumeric_account_len_11_letter_start",
			input: `Account: a2345678901`,
		},
		{
			name:  "alphanumeric_account_len_11_letter_middle",
			input: `Account: 12345a78901`,
		},
		{
			name:  "alphanumeric_account_len_11_letter_end",
			input: `Account: 1234567890a`,
		},
		{
			name:  "alphanumeric_account_len_12_letter_start",
			input: `Account: a23456789012`,
		},
		{
			name:  "alphanumeric_account_len_12_letter_middle",
			input: `Account: 123456a89012`,
		},
		{
			name:  "alphanumeric_account_len_12_letter_end",
			input: `Account: 12345678901a`,
		},
		{
			name:  "alphanumeric_account_len_13_letter_start",
			input: `Account: a234567890123`,
		},
		{
			name:  "alphanumeric_account_len_13_letter_middle",
			input: `Account: 123456a890123`,
		},
		{
			name:  "alphanumeric_account_len_13_letter_end",
			input: `Account: 123456789012a`,
		},
		{
			name:  "alphanumeric_account_len_14_letter_start",
			input: `Account: a2345678901234`,
		},
		{
			name:  "alphanumeric_account_len_14_letter_middle",
			input: `Account: 1234567a901234`,
		},
		{
			name:  "alphanumeric_account_len_14_letter_end",
			input: `Account: 1234567890123a`,
		},
		{
			name:  "alphanumeric_account_len_15_letter_start",
			input: `Account: a23456789012345`,
		},
		{
			name:  "alphanumeric_account_len_15_letter_middle",
			input: `Account: 1234567a9012345`,
		},
		{
			name:  "alphanumeric_account_len_15_letter_end",
			input: `Account: 12345678901234a`,
		},
		{
			name:  "alphanumeric_account_len_16_letter_start",
			input: `Account: a234567890123456`,
		},
		{
			name:  "alphanumeric_account_len_16_letter_middle",
			input: `Account: 12345678a0123456`,
		},
		{
			name:  "alphanumeric_account_len_16_letter_end",
			input: `Account: 123456789012345a`,
		},
		{
			name:  "alphanumeric_account_len_17_letter_start",
			input: `Account: a2345678901234567`,
		},
		{
			name:  "alphanumeric_account_len_17_letter_middle",
			input: `Account: 12345678a01234567`,
		},
		{
			name:  "alphanumeric_account_len_17_letter_end",
			input: `Account: 1234567890123456a`,
		},
		{
			name:  "account_len_18",
			input: `Account: 123456789012345678`,
		},
		{
			name:  "dash_separated",
			input: `Account: 1234-5678-9012`,
		},
		{
			name:  "space_separated",
			input: `Account: 1234 5678 9012`,
		},
		{
			name:  "ssn_dash_format",
			input: `Account: 123-45-6789`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if len(got) != 0 {
				t.Errorf("Detect() got %v secrets, want 0", len(got))
			}
		})
	}
}

func buildExpectedResult(raw []byte, likelihood sensitiveinformation.Likelihood) sensitiveinformation.SensitiveInformation {
	return sensitiveinformation.SensitiveInformation{
		InfoType: sensitiveinformation.InfoType{
			Name:        "US_BANK_ACCOUNT_NUMBER",
			Sensitivity: sensitiveinformation.SensitivityLevelHigh,
		},
		Likelihood: likelihood,
		Raw:        raw,
	}
}
