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

// Package osvecosystem_test contains tests for the osvecosystem package.
package osvecosystem_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/osv-scalibr/inventory/osvecosystem"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

type testCase struct {
	string string
	parsed osvecosystem.Parsed
}

func buildCases(t *testing.T) []testCase {
	t.Helper()

	return []testCase{
		{
			string: "crates.io",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemCratesIO,
				Suffix:    "",
			},
		},
		{
			string: "npm",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemNPM,
				Suffix:    "",
			},
		},
		{
			string: "Debian: ",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemDebian,
				Suffix:    " ",
			},
		},
		{
			string: "Debian::",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemDebian,
				Suffix:    ":",
			},
		},
		{
			string: "Alpine",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemAlpine,
				Suffix:    "",
			},
		},
		{
			string: "Alpine:v",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemAlpine,
				Suffix:    "v",
			},
		},
		{
			string: "Alpine:v3.16",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemAlpine,
				Suffix:    "v3.16",
			},
		},
		{
			string: "Alpine:3.16",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemAlpine,
				Suffix:    "3.16",
			},
		},
		{
			string: "Maven",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemMaven,
				Suffix:    "",
			},
		},
		{
			string: "Maven:https://maven.google.com",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemMaven,
				Suffix:    "https://maven.google.com",
			},
		},
		{
			string: "Photon OS",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemPhotonOS,
				Suffix:    "",
			},
		},
		{
			string: "Photon OS:abc",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemPhotonOS,
				Suffix:    "abc",
			},
		},
		{
			string: "Photon OS:3.0",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemPhotonOS,
				Suffix:    "3.0",
			},
		},
		{
			string: "Red Hat",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemRedHat,
				Suffix:    "",
			},
		},
		{
			string: "Red Hat:abc",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemRedHat,
				Suffix:    "abc",
			},
		},
		{
			string: "Red Hat:rhel_aus:8.4::appstream",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemRedHat,
				Suffix:    "rhel_aus:8.4::appstream",
			},
		},
		{
			string: "Ubuntu",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemUbuntu,
				Suffix:    "",
			},
		},
		{
			string: "Ubuntu:Pro",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemUbuntu,
				Suffix:    "Pro",
			},
		},
		{
			string: "Ubuntu:Pro:18.04:LTS",
			parsed: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemUbuntu,
				Suffix:    "Pro:18.04:LTS",
			},
		},
	}
}

func TestParsed_UnmarshalJSON(t *testing.T) {
	tests := buildCases(t)
	for _, tt := range tests {
		t.Run(tt.string, func(t *testing.T) {
			var got osvecosystem.Parsed

			if err := json.Unmarshal([]byte(`"`+tt.string+`"`), &got); err != nil {
				t.Fatalf("Unmarshal() = %v; want no error", err)
			}

			// ensure that the string is unmarshalled into a struct
			if !reflect.DeepEqual(got, tt.parsed) {
				t.Errorf("Unmarshal() = %v; want %v", got, tt.parsed)
			}
		})
	}
}

func TestParsed_UnmarshalJSON_Errors(t *testing.T) {
	tests := []struct {
		input string
		err   string
	}{
		{"1", "json: cannot unmarshal number into Go value of type string"},
		{"{}", "json: cannot unmarshal object into Go value of type string"},
		{"{\"ecosystem\": \"npm\"}", "json: cannot unmarshal object into Go value of type string"},
		{"{\"ecosystem\": \"npm\", \"suffix\": \"\"}", "json: cannot unmarshal object into Go value of type string"},
		{"{\"Ecosystem\": \"npm\", \"Suffix\": \"\"}", "json: cannot unmarshal object into Go value of type string"},
		{"[]", "json: cannot unmarshal array into Go value of type string"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var got osvecosystem.Parsed
			err := json.Unmarshal([]byte(tt.input), &got)

			if err == nil {
				t.Fatalf("Unmarshal() = %v; want an error", err)
			}

			if err.Error() != tt.err {
				t.Fatalf("Unmarshal() = %v; want %v", err.Error(), tt.err)
			}

			if got != (osvecosystem.Parsed{}) {
				t.Fatalf("Unmarshal() = %v; want %v", got, osvecosystem.Parsed{})
			}
		})
	}
}

func TestParsed_MarshalJSON(t *testing.T) {
	tests := buildCases(t)
	for _, tt := range tests {
		t.Run(tt.string, func(t *testing.T) {
			got, err := json.Marshal(tt.parsed)

			if err != nil {
				t.Fatalf("Marshal() = %v; want no error", err)
			}

			// ensure that the struct is marshaled as a string
			want := `"` + tt.string + `"`
			if string(got) != want {
				t.Errorf("Marshal() = %v; want %v", string(got), want)
			}
		})
	}
}

func TestParsed_String(t *testing.T) {
	tests := buildCases(t)
	for _, tt := range tests {
		t.Run(tt.string, func(t *testing.T) {
			if got := tt.parsed.String(); got != tt.string {
				t.Errorf("String() = %v, want %v", got, tt.string)
			}
		})
	}
}

func TestParse(t *testing.T) {
	tests := buildCases(t)
	for _, tt := range tests {
		t.Run(tt.string, func(t *testing.T) {
			if got := osvecosystem.MustParse(tt.string); !reflect.DeepEqual(got, tt.parsed) {
				t.Errorf("Parse() = %v, want %v", got, tt.parsed)
			}
		})
	}
}
