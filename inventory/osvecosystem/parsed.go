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

// Package osvecosystem provides the Parsed type which represents an OSV ecosystem string.
package osvecosystem

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// Parsed represents an ecosystem-with-suffix string as defined by the [spec], parsed into
// a structured format.
//
// The suffix is optional and is separated from the ecosystem by a colon.
//
// For example, "Debian:7" would be parsed into Parsed{Ecosystem: constants.EcosystemDebian, Suffix: "7"}
//
// [spec]: https://ossf.github.io/osv-schema/
//
//nolint:recvcheck
type Parsed struct {
	Ecosystem osvschema.Ecosystem
	Suffix    string
}

// IsEmpty returns true if the Ecosystem struct is empty.
func (p Parsed) IsEmpty() bool {
	return p.Ecosystem == ""
}

// Equal returns true if the two Parsed structs are equal.
func (p Parsed) Equal(other Parsed) bool {
	// only care about the minor version if both ecosystems have one
	// otherwise we just assume that they're the same and move on
	if p.Suffix != "" && other.Suffix != "" {
		return p.Ecosystem == other.Ecosystem && p.Suffix == other.Suffix
	}

	return p.Ecosystem == other.Ecosystem
}

func (p Parsed) String() string {
	str := string(p.Ecosystem)

	if p.Suffix != "" {
		str += ":" + p.Suffix
	}

	return str
}

// UnmarshalJSON handles unmarshalls a JSON string into a Parsed struct.
//
// This method implements the json.Unmarshaler interface.
func (p *Parsed) UnmarshalJSON(data []byte) error {
	var str string
	err := json.Unmarshal(data, &str)

	if err != nil {
		return err
	}

	*p, err = Parse(str)

	return err
}

// MarshalJSON handles marshals a Parsed struct into a JSON string.
//
// This method implements the json.Marshaler interface.
func (p Parsed) MarshalJSON() ([]byte, error) {
	return []byte(`"` + p.String() + `"`), nil
}

// GetValidity checks if the ecosystem is a valid OSV ecosystem value. Returns nil if valid, error otherwise.
func (p Parsed) GetValidity() error {
	if p.IsEmpty() {
		return nil
	}

	// Missing ecosystems here would be caught by the "exhaustive" linter
	switch p.Ecosystem {
	case osvschema.EcosystemAlmaLinux,
		osvschema.EcosystemAlpaquita,
		osvschema.EcosystemAlpine,
		osvschema.EcosystemAndroid,
		osvschema.EcosystemBellSoftHardenedContainers,
		osvschema.EcosystemBioconductor,
		osvschema.EcosystemBitnami,
		osvschema.EcosystemChainguard,
		osvschema.EcosystemConanCenter,
		osvschema.EcosystemCRAN,
		osvschema.EcosystemCratesIO,
		osvschema.EcosystemDebian,
		osvschema.EcosystemGHC,
		osvschema.EcosystemGitHubActions,
		osvschema.EcosystemGo,
		osvschema.EcosystemHackage,
		osvschema.EcosystemHex,
		osvschema.EcosystemKubernetes,
		osvschema.EcosystemLinux,
		osvschema.EcosystemMageia,
		osvschema.EcosystemMaven,
		osvschema.EcosystemMinimOS,
		osvschema.EcosystemNPM,
		osvschema.EcosystemNuGet,
		osvschema.EcosystemOpenEuler,
		osvschema.EcosystemOpenSUSE,
		osvschema.EcosystemOSSFuzz,
		osvschema.EcosystemPackagist,
		osvschema.EcosystemPhotonOS,
		osvschema.EcosystemPub,
		osvschema.EcosystemPyPI,
		osvschema.EcosystemRedHat,
		osvschema.EcosystemRockyLinux,
		osvschema.EcosystemRubyGems,
		osvschema.EcosystemSUSE,
		osvschema.EcosystemSwiftURL,
		osvschema.EcosystemUbuntu,
		osvschema.EcosystemWolfi:

	default:
		return fmt.Errorf("base ecosystem does not exist in osvschema: %q", p.Ecosystem)
	}

	return nil
}

// MustParse parses a string into a constants.Ecosystem and an optional suffix specified with a ":"
// Panics if there is an invalid ecosystem
func MustParse(str string) Parsed {
	parsed, err := Parse(str)
	if err != nil {
		panic("Failed MustParse: " + err.Error())
	}

	return parsed
}

// Parse parses a string into a constants.Ecosystem and an optional suffix specified with a ":"
func Parse(str string) (Parsed, error) {
	// Special case to return an empty ecosystem if str is empty
	// This is not considered an error.
	if str == "" {
		return Parsed{}, nil
	}

	// We will also add a check for whether the ecosystem is valid to have a suffix here.
	// And return an error if not.
	ecosystem, suffix, _ := strings.Cut(str, ":")

	result := Parsed{osvschema.Ecosystem(ecosystem), suffix}

	return result, result.GetValidity()
}

// FromEcosystem creates a Parsed struct from an osvschema.Ecosystem.
func FromEcosystem(ecosystem osvschema.Ecosystem) Parsed {
	return Parsed{Ecosystem: ecosystem}
}
