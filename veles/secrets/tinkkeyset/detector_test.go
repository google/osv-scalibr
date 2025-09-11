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

package tinkkeyset_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/tinkkeyset"
)

func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{tinkkeyset.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "plain json",
			input: `{"primaryKeyId":1976038263,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GhBi7O0TErBM9eTl3UppUGZg","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1976038263,"outputPrefixType":"TINK"}]}`,
			want: []veles.Secret{tinkkeyset.TinkKeySet{
				Content: `{"primaryKeyId":1976038263, "key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey", "value":"GhBi7O0TErBM9eTl3UppUGZg", "keyMaterialType":"SYMMETRIC"}, "status":"ENABLED", "keyId":1976038263, "outputPrefixType":"TINK"}]}`,
			}},
		},
		{
			name: "pretty json",
			input: `{
				"primaryKeyId":1976038263,
				"key":[
					{
						"keyData":{
							"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
							"value":"GhBi7O0TErBM9eTl3UppUGZg",
							"keyMaterialType":"SYMMETRIC"
							},
						"status":"ENABLED",
						"keyId":1976038263,
						"outputPrefixType":"TINK"
					}
				]
			}`,
			want: []veles.Secret{tinkkeyset.TinkKeySet{
				Content: `{"primaryKeyId":1976038263, "key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey", "value":"GhBi7O0TErBM9eTl3UppUGZg", "keyMaterialType":"SYMMETRIC"}, "status":"ENABLED", "keyId":1976038263, "outputPrefixType":"TINK"}]}`,
			}},
		},
		{
			name:  "multiple keys json",
			input: `{"primaryKeyId":65177451,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GhBcKD0QJVkaSbbFnrmuIV+e","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":65177451,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiCPZRivnJJeqCAXGJemTND9SmOMQkCwxbHGUXGoRmvZcw==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":3858149861,"outputPrefixType":"TINK"}]}`,
			want: []veles.Secret{tinkkeyset.TinkKeySet{
				Content: `{"primaryKeyId":65177451,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GhBcKD0QJVkaSbbFnrmuIV+e","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":65177451,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiCPZRivnJJeqCAXGJemTND9SmOMQkCwxbHGUXGoRmvZcw==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":3858149861,"outputPrefixType":"TINK"}]}`,
			}},
		},
		{
			name:  "base64 encoded binary",
			input: "CPHv2PIDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEEL4HoapXqtkjiMgDxdcNUMYARABGPHv2PIDIAE=",
			want: []veles.Secret{tinkkeyset.TinkKeySet{
				Content: `{"primaryKeyId":1045837809,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GhBC+B6GqV6rZI4jIA8XXDVD","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1045837809,"outputPrefixType":"TINK"}]}`,
			}},
		},
		{
			name:  "base64 encoded json",
			input: "eyJwcmltYXJ5S2V5SWQiOjEwNDU4Mzc4MDksImtleSI6W3sia2V5RGF0YSI6eyJ0eXBlVXJsIjoidHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5IiwidmFsdWUiOiJHaEJDK0I2R3FWNnJaSTRqSUE4WFhEVkQiLCJrZXlNYXRlcmlhbFR5cGUiOiJTWU1NRVRSSUMifSwic3RhdHVzIjoiRU5BQkxFRCIsImtleUlkIjoxMDQ1ODM3ODA5LCJvdXRwdXRQcmVmaXhUeXBlIjoiVElOSyJ9XX0=",
			want: []veles.Secret{tinkkeyset.TinkKeySet{
				Content: `{"primaryKeyId":1045837809,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GhBC+B6GqV6rZI4jIA8XXDVD","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1045837809,"outputPrefixType":"TINK"}]}`,
			}},
		},
		{
			name:  "base64 encoded pretty json",
			input: "ewoJCQkJInByaW1hcnlLZXlJZCI6MTk3NjAzODI2MywKCQkJCSJrZXkiOlsKCQkJCQl7CgkJCQkJCSJrZXlEYXRhIjp7CgkJCQkJCQkidHlwZVVybCI6InR5cGUuZ29vZ2xlYXBpcy5jb20vZ29vZ2xlLmNyeXB0by50aW5rLkFlc0djbUtleSIsCgkJCQkJCQkidmFsdWUiOiJHaEJpN08wVEVyQk05ZVRsM1VwcFVHWmciLAoJCQkJCQkJImtleU1hdGVyaWFsVHlwZSI6IlNZTU1FVFJJQyIKCQkJCQkJCX0sCgkJCQkJCSJzdGF0dXMiOiJFTkFCTEVEIiwKCQkJCQkJImtleUlkIjoxOTc2MDM4MjYzLAoJCQkJCQkib3V0cHV0UHJlZml4VHlwZSI6IlRJTksiCgkJCQkJfQoJCQkJXQoJCQl9Cg==",
			want: []veles.Secret{tinkkeyset.TinkKeySet{
				Content: `{"primaryKeyId":1976038263,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GhBi7O0TErBM9eTl3UppUGZg","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1976038263,"outputPrefixType":"TINK"}]}`,
			}},
		},
		{
			name: "nested escaped json",
			input: `{
				"prop1": 1,
				"key": "{\"primaryKeyId\":1976038263,\n\"key\":[{\"keyData\":{\"typeUrl\":\"type.googleapis.com/google.crypto.tink.AesGcmKey\",\"value\":\"GhBi7O0TErBM9eTl3UppUGZg\",\"keyMaterialType\":\"SYMMETRIC\"},\"status\":\"ENABLED\",\"keyId\":1976038263,\"outputPrefixType\":\"TINK\"}]}",
				"prop2": "test"
			}`,
			want: []veles.Secret{tinkkeyset.TinkKeySet{
				Content: `{"primaryKeyId":1976038263,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GhBi7O0TErBM9eTl3UppUGZg","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1976038263,"outputPrefixType":"TINK"}]}`,
			}},
		},
		{
			name: "double nested escaped json",
			input: `{
				"prop1": 1,
				"key": "{\"sub-key\":\""{\\"primaryKeyId\\":1976038263,\\"key\\":[{\\"keyData\\":{\\"typeUrl\\":\\"type.googleapis.com/google.crypto.tink.AesGcmKey\\",\\"value\\":\\"GhBi7O0TErBM9eTl3UppUGZg\\",\\"keyMaterialType\\":\\"SYMMETRIC\\"},\\"status\\":\\"ENABLED\\",\\"keyId\\":1976038263,\\"outputPrefixType\\":\\"TINK\\"}]}\\"\"}",
				"prop2": "test"
			}`,
			want: []veles.Secret{tinkkeyset.TinkKeySet{
				Content: `{"primaryKeyId":1976038263,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GhBi7O0TErBM9eTl3UppUGZg","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1976038263,"outputPrefixType":"TINK"}]}`,
			}},
		},
		{
			name: "nested base64 encoded json",
			input: `{
				"prop1": 1,
				"key": "eyJwcmltYXJ5S2V5SWQiOjEwNDU4Mzc4MDksImtleSI6W3sia2V5RGF0YSI6eyJ0eXBlVXJsIjoidHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5IiwidmFsdWUiOiJHaEJDK0I2R3FWNnJaSTRqSUE4WFhEVkQiLCJrZXlNYXRlcmlhbFR5cGUiOiJTWU1NRVRSSUMifSwic3RhdHVzIjoiRU5BQkxFRCIsImtleUlkIjoxMDQ1ODM3ODA5LCJvdXRwdXRQcmVmaXhUeXBlIjoiVElOSyJ9XX0=",
				"prop2": "test"
			}`,
			want: []veles.Secret{tinkkeyset.TinkKeySet{
				Content: `{"primaryKeyId":1045837809,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GhBC+B6GqV6rZI4jIA8XXDVD","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1045837809,"outputPrefixType":"TINK"}]}`,
			}},
		},
		{
			name: "nested base64 encoded binary yml",
			input: `
			something_else:
				- 1
				- 2
			something:
				key: CMqC1egBEu0BCuABCjZ0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5FY2RzYVByaXZhdGVLZXkSowESbhIGCAIQAxgCGjEALtEnNfLN9e2OEVYeweLj35F9/Tzr2kV+YZUmV4wR2lgYBTu6JAujO3+iJvtiQi5EIjEAHFyd64L5Uox0INu7FL3WGz5/BBUmNhEssMoaGJQKYisImuXu4KX6j+3bpHP4LTR7GjEAs0ZzCdzmNyaHnqGtYNywvw8AvkJv9zemuyXIRmmLPj/eR+Uwzn8cXasTrw5dD+ESGAIQARjKgtXoASAD
			`,
			want: []veles.Secret{tinkkeyset.TinkKeySet{
				Content: `{"primaryKeyId":487932234,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.EcdsaPrivateKey","value":"Em4SBggCEAMYAhoxAC7RJzXyzfXtjhFWHsHi49+Rff0869pFfmGVJleMEdpYGAU7uiQLozt/oib7YkIuRCIxABxcneuC+VKMdCDbuxS91hs+fwQVJjYRLLDKGhiUCmIrCJrl7uCl+o/t26Rz+C00exoxALNGcwnc5jcmh56hrWDcsL8PAL5Cb/c3prslyEZpiz4/3kflMM5/HF2rE68OXQ/hEg==","keyMaterialType":"ASYMMETRIC_PRIVATE"},"status":"ENABLED","keyId":487932234,"outputPrefixType":"RAW"}]}`,
			}},
		},
	}

	// TODO: shouldn't be necessary
	cmpOpt := cmp.Comparer(func(x, y tinkkeyset.TinkKeySet) bool {
		var xJSON, yJSON any
		if err := json.Unmarshal([]byte(x.Content), &xJSON); err != nil {
			return false
		}
		if err := json.Unmarshal([]byte(y.Content), &yJSON); err != nil {
			return false
		}
		return cmp.Equal(xJSON, yJSON)
	})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty(), cmpOpt); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{tinkkeyset.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name: "test",
			input: `{
				"encryptedKeyset":"AdeMbh3U2oN9f4wR2wm6qMNqDNRsRoYonk+13vlyDIHSSob8c7KHDr1oBntEOz+Un2jQIzVBj2YzxgmtFRwa5TBW7xElrsJsNpDu8UtIPPX/5yAI9mO8Pf0gKK242lDnefciNpX6FXWRB6mxwklXKxF2v1eY2uxIII2ZG/ETuQ09L3Sn1FcSjYPeyy0Bi5ov7uTDNFJ5uU1LgGeGYmwlxK7QE/bCG7Ww+iCo/JdR/kNL5bdSp1q8ywcUk/1RDR9FnGx3XA8crFjAVbeMPgSIBJ1N7a69dQyttVawwm+3GyLCMB6gfqLLKbnuBpXb45/mhQdml6/U6cLxOZlxEOzU0GoC2bjQ7+qneTWwmDsNPgkwxjaNVm8p",
				"keysetInfo":{
					"primaryKeyId":1519620947,
					"keyInfo":[
						{
						"typeUrl":"type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
						"status":"ENABLED","keyId":1519620947,"outputPrefixType":"RAW"
						}
					]
				}
			}`,
			want: []veles.Secret{},
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
