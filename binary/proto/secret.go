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
	"fmt"

	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/veles"
	velesgcpsak "github.com/google/osv-scalibr/veles/secrets/gcpsak"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// --- Struct to Proto

func secretToProto(s *inventory.Secret) (*spb.Secret, error) {
	sec, err := velesSecretToProto(s.Secret)
	if err != nil {
		return nil, err
	}
	res, err := validationResultToProto(s.Validation)
	if err != nil {
		return nil, err
	}
	return &spb.Secret{
		Secret:    sec,
		Status:    res,
		Locations: locationToProto(s.Location),
	}, nil
}

func velesSecretToProto(s veles.Secret) (*spb.SecretData, error) {
	switch t := s.(type) {
	case velesgcpsak.GCPSAK:
		return gcpsakToProto(t), nil
	default:
		return nil, fmt.Errorf("unsupported veles.Secret of type %T", s)
	}
}

func gcpsakToProto(sak velesgcpsak.GCPSAK) *spb.SecretData {
	sakPB := &spb.SecretData_GCPSAK{
		PrivateKeyId: sak.PrivateKeyID,
		ClientEmail:  sak.ServiceAccount,
		Signature:    sak.Signature,
	}
	if sak.Extra != nil {
		sakPB.Type = sak.Extra.Type
		sakPB.ProjectId = sak.Extra.ProjectID
		sakPB.ClientId = sak.Extra.ClientID
		sakPB.AuthUri = sak.Extra.AuthURI
		sakPB.TokenUri = sak.Extra.TokenURI
		sakPB.AuthProviderX509CertUrl = sak.Extra.AuthProviderX509CertURL
		sakPB.ClientX509CertUrl = sak.Extra.ClientX509CertURL
		sakPB.UniverseDomain = sak.Extra.UniverseDomain
		sakPB.PrivateKey = sak.Extra.PrivateKey
	}
	return &spb.SecretData{
		Secret: &spb.SecretData_Gcpsak{
			Gcpsak: sakPB,
		},
	}
}

func validationResultToProto(r inventory.SecretValidationResult) (*spb.SecretStatus, error) {
	status, err := validationStatusToProto(r.Status)
	if err != nil {
		return nil, err
	}
	return &spb.SecretStatus{
		Status:      status,
		LastUpdated: timestamppb.New(r.At),
	}, nil
}

func validationStatusToProto(s veles.ValidationStatus) (spb.SecretStatus_SecretStatusEnum, error) {
	switch s {
	case veles.ValidationUnspecified:
		return spb.SecretStatus_UNSPECIFIED, nil
	case veles.ValidationUnsupported:
		return spb.SecretStatus_UNKNOWN, nil
	case veles.ValidationFailed:
		return spb.SecretStatus_UNKNOWN, nil
	case veles.ValidationInvalid:
		return spb.SecretStatus_INVALID, nil
	case veles.ValidationValid:
		return spb.SecretStatus_VALID, nil
	default:
		return spb.SecretStatus_UNSPECIFIED, fmt.Errorf("unsupported veles.ValidationStatus %q", s)
	}
}

func locationToProto(filepath string) []*spb.Location {
	return []*spb.Location{
		{
			Location: &spb.Location_Filepath{
				Filepath: &spb.Filepath{
					Path: filepath,
				},
			},
		},
	}
}
