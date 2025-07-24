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

	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

var (
	// --- Errors

	// ErrAdvisoryMissing will be returned if the Advisory is not set on a finding.
	ErrAdvisoryMissing = errors.New("advisory missing in finding")

	// ErrAdvisoryIDMissing will be returned if the Advisory ID is not set on a finding.
	ErrAdvisoryIDMissing = errors.New("advisory ID missing in finding")

	genericFindingSeverityEnumToProto = map[inventory.SeverityEnum]spb.SeverityEnum{
		inventory.SeverityMinimal:     spb.SeverityEnum_MINIMAL,
		inventory.SeverityLow:         spb.SeverityEnum_LOW,
		inventory.SeverityMedium:      spb.SeverityEnum_MEDIUM,
		inventory.SeverityHigh:        spb.SeverityEnum_HIGH,
		inventory.SeverityCritical:    spb.SeverityEnum_CRITICAL,
		inventory.SeverityUnspecified: spb.SeverityEnum_SEVERITY_UNSPECIFIED,
	}

	genericFindingSeverityEnumToStruct = func() map[spb.SeverityEnum]inventory.SeverityEnum {
		m := make(map[spb.SeverityEnum]inventory.SeverityEnum)
		for k, v := range genericFindingSeverityEnumToProto {
			m[v] = k
		}
		if len(m) != len(genericFindingSeverityEnumToProto) {
			panic("genericFindingSeverityEnumToProto does not contain all values from genericFindingSeverityEnumToStruct")
		}
		return m
	}()
)

// --- Struct to Proto

// GenericFindingToProto converts a GenericFinding go struct into the equivalent proto.
func GenericFindingToProto(f *inventory.GenericFinding) (*spb.GenericFinding, error) {
	if f == nil {
		return nil, nil
	}
	if f.Adv == nil {
		return nil, ErrAdvisoryMissing
	}
	if f.Adv.ID == nil {
		return nil, ErrAdvisoryIDMissing
	}

	var target *spb.GenericFindingTargetDetails
	if f.Target != nil {
		target = &spb.GenericFindingTargetDetails{
			Extra: f.Target.Extra,
		}
	}

	var exps []*spb.FindingExploitabilitySignal
	for _, exp := range f.ExploitabilitySignals {
		expProto := FindingVEXToProto(exp)
		exps = append(exps, expProto)
	}

	return &spb.GenericFinding{
		Adv: &spb.GenericFindingAdvisory{
			Id: &spb.AdvisoryId{
				Publisher: f.Adv.ID.Publisher,
				Reference: f.Adv.ID.Reference,
			},
			Title:          f.Adv.Title,
			Description:    f.Adv.Description,
			Recommendation: f.Adv.Recommendation,
			Sev:            genericFindingSeverityEnumToProto[f.Adv.Sev],
		},
		Target:                target,
		Plugins:               f.Plugins,
		ExploitabilitySignals: exps,
	}, nil
}

// --- Proto to Struct

// GenericFindingToStruct converts a GenericFinding proto into the equivalent go struct.
func GenericFindingToStruct(f *spb.GenericFinding) (*inventory.GenericFinding, error) {
	if f == nil {
		return nil, nil
	}
	if f.Adv == nil {
		return nil, ErrAdvisoryMissing
	}
	if f.Adv.Id == nil {
		return nil, ErrAdvisoryIDMissing
	}

	target := &inventory.GenericFindingTargetDetails{
		Extra: f.Target.GetExtra(),
	}

	var exps []*vex.FindingExploitabilitySignal
	for _, exp := range f.GetExploitabilitySignals() {
		expStruct := FindingVEXToStruct(exp)
		exps = append(exps, expStruct)
	}

	return &inventory.GenericFinding{
		Adv: &inventory.GenericFindingAdvisory{
			ID: &inventory.AdvisoryID{
				Publisher: f.Adv.Id.GetPublisher(),
				Reference: f.Adv.Id.GetReference(),
			},
			Title:          f.Adv.GetTitle(),
			Description:    f.Adv.GetDescription(),
			Recommendation: f.Adv.GetRecommendation(),
			Sev:            genericFindingSeverityEnumToStruct[f.Adv.GetSev()],
		},
		Target:                target,
		Plugins:               f.GetPlugins(),
		ExploitabilitySignals: exps,
	}, nil
}
