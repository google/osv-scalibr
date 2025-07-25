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
	"fmt"
	"time"

	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/veles"
	velesgcpsak "github.com/google/osv-scalibr/veles/secrets/gcpsak"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	// --- Errors

	// ErrMultipleSecretLocations will be returned if multiple secret locations are set.
	ErrMultipleSecretLocations = errors.New("multiple secret locations are not supported")

	// ErrUnsupportedValidationType will be returned if the validation type is not supported.
	ErrUnsupportedValidationType = errors.New("validation type is not supported")

	// ErrUnsupportedSecretType will be returned if the secret type is not supported.
	ErrUnsupportedSecretType = errors.New("unsupported secret type")

	structToProtoValidation = map[veles.ValidationStatus]spb.SecretStatus_SecretStatusEnum{
		veles.ValidationUnspecified: spb.SecretStatus_UNSPECIFIED,
		veles.ValidationUnsupported: spb.SecretStatus_UNSUPPORTED,
		veles.ValidationFailed:      spb.SecretStatus_FAILED,
		veles.ValidationInvalid:     spb.SecretStatus_INVALID,
		veles.ValidationValid:       spb.SecretStatus_VALID,
	}

	protoToStructValidation = func() map[spb.SecretStatus_SecretStatusEnum]veles.ValidationStatus {
		m := make(map[spb.SecretStatus_SecretStatusEnum]veles.ValidationStatus)
		for k, v := range structToProtoValidation {
			m[v] = k
		}
		if len(m) != len(structToProtoValidation) {
			panic("protoToStructValidation does not contain all values from structToProtoValidation")
		}
		return m
	}()
)

// --- Struct to Proto

// SecretToProto converts a struct Secret to its proto representation.
func SecretToProto(s *inventory.Secret) (*spb.Secret, error) {
	if s == nil {
		return nil, nil
	}

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
		Locations: secretLocationToProto(s.Location),
	}, nil
}

func velesSecretToProto(s veles.Secret) (*spb.SecretData, error) {
	switch t := s.(type) {
	case velesgcpsak.GCPSAK:
		return gcpsakToProto(t), nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedSecretType, s)
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

	var lastUpdate *timestamppb.Timestamp
	if !r.At.IsZero() {
		lastUpdate = timestamppb.New(r.At)
	}

	// Prefer nil over empty proto.
	if lastUpdate == nil && status == spb.SecretStatus_UNSPECIFIED {
		return nil, nil
	}

	return &spb.SecretStatus{
		Status:      status,
		LastUpdated: lastUpdate,
	}, nil
}

func validationStatusToProto(s veles.ValidationStatus) (spb.SecretStatus_SecretStatusEnum, error) {
	v, ok := structToProtoValidation[s]
	if !ok {
		return spb.SecretStatus_UNSPECIFIED, fmt.Errorf("%w: %q", ErrUnsupportedValidationType, s)
	}
	return v, nil
}

func secretLocationToProto(filepath string) []*spb.Location {
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

// --- Proto to Struct

// SecretToStruct converts a proto Secret to its struct representation.
func SecretToStruct(s *spb.Secret) (*inventory.Secret, error) {
	if s == nil {
		return nil, nil
	}

	if len(s.GetLocations()) > 1 {
		return nil, ErrMultipleSecretLocations
	}

	sec, err := velesSecretToStruct(s.GetSecret())
	if err != nil {
		return nil, err
	}
	res, err := validationResultToStruct(s.GetStatus())
	if err != nil {
		return nil, err
	}
	var path string
	if len(s.GetLocations()) > 0 {
		path = secretLocationToStruct(s.GetLocations()[0])
	}

	return &inventory.Secret{
		Secret:     sec,
		Location:   path,
		Validation: res,
	}, nil
}

func velesSecretToStruct(s *spb.SecretData) (veles.Secret, error) {
	switch s.Secret.(type) {
	case *spb.SecretData_Gcpsak:
		return gcpsakToStruct(s.GetGcpsak()), nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedSecretType, s.GetSecret())
	}
}

func gcpsakToStruct(sakPB *spb.SecretData_GCPSAK) velesgcpsak.GCPSAK {
	sak := velesgcpsak.GCPSAK{
		PrivateKeyID:   sakPB.GetPrivateKeyId(),
		ServiceAccount: sakPB.GetClientEmail(),
		Signature:      sakPB.GetSignature(),
	}
	if sakPB.GetType() != "" {
		sak.Extra = &velesgcpsak.ExtraFields{
			Type:                    sakPB.GetType(),
			ProjectID:               sakPB.GetProjectId(),
			ClientID:                sakPB.GetClientId(),
			AuthURI:                 sakPB.GetAuthUri(),
			TokenURI:                sakPB.GetTokenUri(),
			AuthProviderX509CertURL: sakPB.GetAuthProviderX509CertUrl(),
			ClientX509CertURL:       sakPB.GetClientX509CertUrl(),
			UniverseDomain:          sakPB.GetUniverseDomain(),
			PrivateKey:              sakPB.GetPrivateKey(),
		}
	}
	return sak
}

func validationResultToStruct(r *spb.SecretStatus) (inventory.SecretValidationResult, error) {
	status, err := validationStatusToStruct(r.GetStatus())
	if err != nil {
		return inventory.SecretValidationResult{}, err
	}
	var at time.Time
	if r.GetLastUpdated() != nil {
		at = r.GetLastUpdated().AsTime()
	}
	return inventory.SecretValidationResult{
		Status: status,
		At:     at,
	}, nil
}

func validationStatusToStruct(s spb.SecretStatus_SecretStatusEnum) (veles.ValidationStatus, error) {
	v, ok := protoToStructValidation[s]
	if !ok {
		return veles.ValidationUnspecified, fmt.Errorf("%w: %q", ErrUnsupportedValidationType, s)
	}
	return v, nil
}

func secretLocationToStruct(location *spb.Location) string {
	if location.GetFilepath() != nil {
		return location.GetFilepath().GetPath()
	}
	return ""
}
