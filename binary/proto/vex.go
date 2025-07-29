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

package proto

import (
	"errors"

	"github.com/google/osv-scalibr/inventory/vex"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

var (
	// --- Errors

	// ErrVulnIdentifiersAndMatchsAllSet will be returned if both VulnIdentifiers and MatchesAllVulns are set.
	ErrVulnIdentifiersAndMatchsAllSet = errors.New("cannot set both VulnIdentifiers and MatchesAllVulns")

	// structToProtoVEX is a map of struct VEX justifications to their corresponding proto values.
	structToProtoVEX = map[vex.Justification]spb.VexJustification{
		vex.Unspecified:                                 spb.VexJustification_VEX_JUSTIFICATION_UNSPECIFIED,
		vex.ComponentNotPresent:                         spb.VexJustification_COMPONENT_NOT_PRESENT,
		vex.VulnerableCodeNotPresent:                    spb.VexJustification_VULNERABLE_CODE_NOT_PRESENT,
		vex.VulnerableCodeNotInExecutePath:              spb.VexJustification_VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
		vex.VulnerableCodeCannotBeControlledByAdversary: spb.VexJustification_VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY,
		vex.InlineMitigationAlreadyExists:               spb.VexJustification_INLINE_MITIGATION_ALREADY_EXISTS,
	}
	// protoToStructVEX is a map of proto VEX justifications to their corresponding struct values.
	// It is initialized from structToProtoVEX during runtime to ensure both maps are in sync.
	protoToStructVEX = func() map[spb.VexJustification]vex.Justification {
		m := make(map[spb.VexJustification]vex.Justification)
		for k, v := range structToProtoVEX {
			m[v] = k
		}
		if len(m) != len(structToProtoVEX) {
			panic("protoToStructAnnotations does not contain all values from structToProtoAnnotations")
		}
		return m
	}()
)

// --- Struct to Proto

// PackageVEXToProto converts a struct PackageExploitabilitySignal to its proto representation.
func PackageVEXToProto(v *vex.PackageExploitabilitySignal) (*spb.PackageExploitabilitySignal, error) {
	if v == nil {
		return nil, nil
	}
	if len(v.VulnIdentifiers) != 0 && v.MatchesAllVulns {
		return nil, ErrVulnIdentifiersAndMatchsAllSet
	}

	p := &spb.PackageExploitabilitySignal{
		Plugin:        v.Plugin,
		Justification: structToProtoVEX[v.Justification],
	}
	if v.MatchesAllVulns {
		p.VulnFilter = &spb.PackageExploitabilitySignal_MatchesAllVulns{MatchesAllVulns: true}
	} else {
		p.VulnFilter = &spb.PackageExploitabilitySignal_VulnIdentifiers{
			VulnIdentifiers: &spb.VulnIdentifiers{Identifiers: v.VulnIdentifiers},
		}
	}
	return p, nil
}

// FindingVEXToProto converts a struct FindingExploitabilitySignal to its proto representation.
func FindingVEXToProto(v *vex.FindingExploitabilitySignal) *spb.FindingExploitabilitySignal {
	if v == nil {
		return nil
	}

	return &spb.FindingExploitabilitySignal{
		Plugin:        v.Plugin,
		Justification: structToProtoVEX[v.Justification],
	}
}

// --- Proto to Struct

// PackageVEXToStruct converts a proto PackageExploitabilitySignal to its struct representation.
func PackageVEXToStruct(p *spb.PackageExploitabilitySignal) (*vex.PackageExploitabilitySignal, error) {
	if p == nil {
		return nil, nil
	}

	v := &vex.PackageExploitabilitySignal{
		Plugin:        p.Plugin,
		Justification: protoToStructVEX[p.Justification],
	}
	if ids := p.GetVulnIdentifiers(); ids != nil {
		v.VulnIdentifiers = ids.Identifiers
	} else {
		v.MatchesAllVulns = p.GetMatchesAllVulns()
	}
	return v, nil
}

// FindingVEXToStruct converts a proto FindingExploitabilitySignal to its struct representation.
func FindingVEXToStruct(p *spb.FindingExploitabilitySignal) *vex.FindingExploitabilitySignal {
	if p == nil {
		return nil
	}

	return &vex.FindingExploitabilitySignal{
		Plugin:        p.Plugin,
		Justification: protoToStructVEX[p.Justification],
	}
}
