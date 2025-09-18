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

package azurestorageaccountaccesskey_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/azurestorageaccountaccesskey"
)

// Azure Storage account access key is composed by 86 base64 characters followed by '=='
// Reference:
// https://learn.microsoft.com/en-us/purview/sit-defn-azure-storage-account-key-generic
const testKey = `YutGV0Vlauqsobd6tPWz2AKwHhBXMEWsAH+rSbz0UZUfaMVj1CFrcNQK47ygmrC4vHmc7eOp1LdM+AStk5mMYA==`

// TestDetector_truePositives tests for cases where we know the Detector
// will find a valid key/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{azurestorageaccountaccesskey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: testKey,
		want: []veles.Secret{
			azurestorageaccountaccesskey.AzureStorageAccountAccessKey{Key: testKey},
		},
	}, {
		// According to Microsoft documentation the key can start with
		// zero to one of the greater than symbol (>), apostrophe ('),
		// equal sign (=), quotation mark (?), or number sign (#)
		// Therefore the equal sign after the api key should be present in the result
		name:  "match at end of string",
		input: `API_KEY=` + testKey,
		want: []veles.Secret{
			azurestorageaccountaccesskey.AzureStorageAccountAccessKey{Key: `=` + testKey},
		},
	}, {
		name:  "match in middle of string",
		input: `API_KEY="` + testKey + `"`,
		want: []veles.Secret{
			azurestorageaccountaccesskey.AzureStorageAccountAccessKey{Key: testKey},
		},
	}, {
		name:  "multiple matches",
		input: testKey + testKey + testKey,
		want: []veles.Secret{
			azurestorageaccountaccesskey.AzureStorageAccountAccessKey{Key: testKey},
			azurestorageaccountaccesskey.AzureStorageAccountAccessKey{Key: testKey},
			azurestorageaccountaccesskey.AzureStorageAccountAccessKey{Key: testKey},
		},
	}, {
		name:  "multiple distinct matches",
		input: testKey + "\n" + "1" + testKey[1:] + "\n",
		want: []veles.Secret{
			azurestorageaccountaccesskey.AzureStorageAccountAccessKey{Key: testKey},
			azurestorageaccountaccesskey.AzureStorageAccountAccessKey{Key: "1" + testKey[1:]},
		},
	}, {
		name: "larger input containing key",
		input: fmt.Sprintf(`
CONFIG_FILE=config.txt
API_KEY="%s"
CLOUD_PROJECT=my-project
		`, testKey),
		want: []veles.Secret{
			azurestorageaccountaccesskey.AzureStorageAccountAccessKey{Key: testKey},
		},
	}, {
		name:  "potential match longer than max key length",
		input: testKey + `test`,
		want: []veles.Secret{
			azurestorageaccountaccesskey.AzureStorageAccountAccessKey{Key: testKey},
		},
	}}
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

// TestDetector_trueNegatives tests for cases where we know the Detector
// will not find a valid key.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{azurestorageaccountaccesskey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "empty input",
		input: "",
	}, {
		name:  "short key should not match",
		input: testKey[:len(testKey)-1],
	}, {
		name:  "special character ($) in key should not match",
		input: `Yut$V0Vlauqsobd6tPWz2AKwHhBXMEWsAH+rSbz0UZUfaMVj1CFrcNQK47ygmrC4vHmc7eOp1LdM+AStk5mMYA==`,
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
