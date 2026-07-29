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

package proto

import (
	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/location"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
)

// SensitiveInformationToProto converts an inventory.SensitiveInformation to its proto representation.
func SensitiveInformationToProto(sd *inventory.SensitiveInformation) (*spb.SensitiveInformation, error) {
	if sd == nil {
		return nil, nil
	}
	return &spb.SensitiveInformation{
		InfoType:   sensitiveInformationInfoTypeToProto(sd.Finding.InfoType),
		Likelihood: sensitiveInformationLikelihoodToProtoLikelihood[sd.Finding.Likelihood],
		Raw:        sd.Finding.Raw,
		Location:   LocationToProto(&sd.Location),
	}, nil
}

// sensitiveInformationInfoTypeToProto converts an inventory.InfoType to its proto representation.
func sensitiveInformationInfoTypeToProto(infoType sensitiveinformation.InfoType) *spb.InfoType {
	return &spb.InfoType{
		Name:        infoType.Name,
		Sensitivity: sensitiveInformationSensitivityLevelToProtoSensitivityLevel[infoType.Sensitivity],
	}
}

var sensitiveInformationSensitivityLevelToProtoSensitivityLevel = map[sensitiveinformation.SensitivityLevel]spb.SensitivityLevel{
	sensitiveinformation.SensitivityLevelUnspecified: spb.SensitivityLevel_SENSITIVITY_LEVEL_UNSPECIFIED,
	sensitiveinformation.SensitivityLevelLow:         spb.SensitivityLevel_SENSITIVITY_LEVEL_LOW,
	sensitiveinformation.SensitivityLevelModerate:    spb.SensitivityLevel_SENSITIVITY_LEVEL_MODERATE,
	sensitiveinformation.SensitivityLevelHigh:        spb.SensitivityLevel_SENSITIVITY_LEVEL_HIGH,
}

var sensitiveInformationLikelihoodToProtoLikelihood = map[sensitiveinformation.Likelihood]spb.Likelihood{
	sensitiveinformation.LikelihoodUnspecified: spb.Likelihood_LIKELIHOOD_UNSPECIFIED,
	sensitiveinformation.LikelihoodUnlikely:    spb.Likelihood_LIKELIHOOD_UNLIKELY,
	sensitiveinformation.LikelihoodLikely:      spb.Likelihood_LIKELIHOOD_LIKELY,
	sensitiveinformation.LikelihoodVeryLikely:  spb.Likelihood_LIKELIHOOD_VERY_LIKELY,
}

// SensitiveInformationToStruct converts a spb.SensitiveInformation to its struct representation.
func SensitiveInformationToStruct(sd *spb.SensitiveInformation) (*inventory.SensitiveInformation, error) {
	if sd == nil {
		return nil, nil
	}

	var loc location.Location
	if l := LocationToStruct(sd.Location); l != nil {
		loc = *l
	}

	return &inventory.SensitiveInformation{
		Finding: sensitiveinformation.SensitiveInformation{
			InfoType:   infoTypeToSensitiveInformationInfoType(sd.InfoType),
			Likelihood: protoToSensitiveInformationLikelihood[sd.Likelihood],
			Raw:        sd.Raw,
		},
		Location: loc,
	}, nil
}

func infoTypeToSensitiveInformationInfoType(infoType *spb.InfoType) sensitiveinformation.InfoType {
	if infoType == nil {
		return sensitiveinformation.InfoType{}
	}
	return sensitiveinformation.InfoType{
		Name:        infoType.Name,
		Sensitivity: protoToSensitiveInformationSensitivityLevel[infoType.Sensitivity],
	}
}

var protoToSensitiveInformationSensitivityLevel = map[spb.SensitivityLevel]sensitiveinformation.SensitivityLevel{
	spb.SensitivityLevel_SENSITIVITY_LEVEL_UNSPECIFIED: sensitiveinformation.SensitivityLevelUnspecified,
	spb.SensitivityLevel_SENSITIVITY_LEVEL_LOW:         sensitiveinformation.SensitivityLevelLow,
	spb.SensitivityLevel_SENSITIVITY_LEVEL_MODERATE:    sensitiveinformation.SensitivityLevelModerate,
	spb.SensitivityLevel_SENSITIVITY_LEVEL_HIGH:        sensitiveinformation.SensitivityLevelHigh,
}

var protoToSensitiveInformationLikelihood = map[spb.Likelihood]sensitiveinformation.Likelihood{
	spb.Likelihood_LIKELIHOOD_UNSPECIFIED: sensitiveinformation.LikelihoodUnspecified,
	spb.Likelihood_LIKELIHOOD_UNLIKELY:    sensitiveinformation.LikelihoodUnlikely,
	spb.Likelihood_LIKELIHOOD_LIKELY:      sensitiveinformation.LikelihoodLikely,
	spb.Likelihood_LIKELIHOOD_VERY_LIKELY: sensitiveinformation.LikelihoodVeryLikely,
}
