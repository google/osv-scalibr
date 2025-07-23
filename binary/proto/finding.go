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

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

var (
	// ErrAdvisoryMissing will be returned if the Advisory is not set on a finding.
	ErrAdvisoryMissing = errors.New("advisory missing in finding")

	// ErrAdvisoryIDMissing will be returned if the Advisory ID is not set on a finding.
	ErrAdvisoryIDMissing = errors.New("advisory ID missing in finding")
)

// --- Struct to Proto

func genericFindingToProto(f *inventory.GenericFinding) (*spb.GenericFinding, error) {
	if f.Adv == nil {
		return nil, ErrAdvisoryMissing
	}
	var target *spb.GenericFindingTargetDetails
	if f.Target != nil {
		target = &spb.GenericFindingTargetDetails{
			Extra: f.Target.Extra,
		}
	}
	if f.Adv.ID == nil {
		return nil, ErrAdvisoryIDMissing
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
			Sev:            severityEnumToProto(f.Adv.Sev),
		},
		Target:                target,
		Plugins:               f.Plugins,
		ExploitabilitySignals: findingVEXToProto(f.ExploitabilitySignals),
	}, nil
}

func severityEnumToProto(severity inventory.SeverityEnum) spb.SeverityEnum {
	switch severity {
	case inventory.SeverityMinimal:
		return spb.SeverityEnum_MINIMAL
	case inventory.SeverityLow:
		return spb.SeverityEnum_LOW
	case inventory.SeverityMedium:
		return spb.SeverityEnum_MEDIUM
	case inventory.SeverityHigh:
		return spb.SeverityEnum_HIGH
	case inventory.SeverityCritical:
		return spb.SeverityEnum_CRITICAL
	default:
		return spb.SeverityEnum_SEVERITY_UNSPECIFIED
	}
}

// --- Proto to Struct
