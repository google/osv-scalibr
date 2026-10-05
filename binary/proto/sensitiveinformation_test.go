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

package proto_test

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/binary/proto"
	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/location"
	"github.com/google/osv-scalibr/veles/sensitiveinformation"
	"google.golang.org/protobuf/testing/protocmp"
)

var (
	SensitiveInformationStruct1 = &inventory.SensitiveInformation{
		Finding: sensitiveinformation.SensitiveInformation{
			InfoType: sensitiveinformation.InfoType{
				Name:        "PASSPORT_NUMBER",
				Sensitivity: sensitiveinformation.SensitivityLevelHigh,
			},
			Likelihood: sensitiveinformation.LikelihoodVeryLikely,
			Raw:        []byte("raw-data-123"),
		},
		Location: location.FromPath("foo/bar"),
	}

	SensitiveInformationProto1 = &spb.SensitiveInformation{
		InfoType: &spb.InfoType{
			Name:        "PASSPORT_NUMBER",
			Sensitivity: spb.SensitivityLevel_SENSITIVITY_LEVEL_HIGH,
		},
		Likelihood: spb.Likelihood_LIKELIHOOD_VERY_LIKELY,
		Raw:        []byte("raw-data-123"),
		Location: &spb.Location{
			File: &spb.File{
				Path: "foo/bar",
			},
		},
	}

	SensitiveInformationStructDefault = &inventory.SensitiveInformation{
		Finding: sensitiveinformation.SensitiveInformation{
			InfoType: sensitiveinformation.InfoType{
				Name:        "",
				Sensitivity: sensitiveinformation.SensitivityLevelUnspecified,
			},
			Likelihood: sensitiveinformation.LikelihoodUnspecified,
			Raw:        []byte(""),
		},
		Location: location.Location{},
	}

	SensitiveInformationProtoDefault = &spb.SensitiveInformation{
		InfoType: &spb.InfoType{
			Name:        "",
			Sensitivity: spb.SensitivityLevel_SENSITIVITY_LEVEL_UNSPECIFIED,
		},
		Likelihood: spb.Likelihood_LIKELIHOOD_UNSPECIFIED,
		Raw:        []byte(""),
		Location:   &spb.Location{},
	}
)

func TestSensitiveInformationToProto(t *testing.T) {
	testCases := []struct {
		desc    string
		si      *inventory.SensitiveInformation
		want    *spb.SensitiveInformation
		wantErr error
	}{
		{
			desc: "nil",
			si:   nil,
			want: nil,
		},
		{
			desc: "success",
			si:   SensitiveInformationStruct1,
			want: SensitiveInformationProto1,
		},
		{
			desc: "default info",
			si:   SensitiveInformationStructDefault,
			want: SensitiveInformationProtoDefault,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := proto.SensitiveInformationToProto(tc.si)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("SensitiveInformationToProto(%v) returned error %v, want error %v", tc.si, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Fatalf("SensitiveInformationToProto(%v) returned diff (-want +got):\n%s", tc.si, diff)
			}

			// Test the reverse conversion for completeness.
			gotPB, err := proto.SensitiveInformationToStruct(got)
			if err != nil {
				t.Fatalf("SensitiveInformationToStruct(%v) returned error %v, want nil", got, err)
			}
			if diff := cmp.Diff(tc.si, gotPB, protocmp.Transform()); diff != "" {
				t.Fatalf("SensitiveInformationToStruct(%v) returned diff (-want +got):\n%s", got, diff)
			}
		})
	}
}
