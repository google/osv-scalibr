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

package proto_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/binary/proto"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gcpsak"
	"google.golang.org/protobuf/testing/protocmp"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	secretAt1 = time.Now()

	secretGCPSAKStruct1 = &inventory.Secret{
		Secret: gcpsak.GCPSAK{
			PrivateKeyID:   "some-private-key-id",
			ServiceAccount: "some-service-account@gserviceaccount.iam.google.com",
			Signature:      make([]byte, 256),
		},
		Location: "/foo/bar/baz.json",
		Validation: inventory.SecretValidationResult{
			At:     secretAt1,
			Status: veles.ValidationInvalid,
		},
	}
	secretGCPSAKProto1 = &spb.Secret{
		Secret: &spb.SecretData{
			Secret: &spb.SecretData_Gcpsak{
				Gcpsak: &spb.SecretData_GCPSAK{
					PrivateKeyId: "some-private-key-id",
					ClientEmail:  "some-service-account@gserviceaccount.iam.google.com",
					Signature:    make([]byte, 256),
				},
			},
		},
		Status: &spb.SecretStatus{
			Status:      spb.SecretStatus_INVALID,
			LastUpdated: timestamppb.New(secretAt1),
		},
		Locations: []*spb.Location{
			&spb.Location{
				Location: &spb.Location_Filepath{
					Filepath: &spb.Filepath{
						Path: "/foo/bar/baz.json",
					},
				},
			},
		},
	}
)

// --- Struct to Proto

func TestSecretToProto(t *testing.T) {
	copier := cpy.New(
		cpy.IgnoreAllUnexported(),
	)

	testCases := []struct {
		desc    string
		s       *inventory.Secret
		want    *spb.Secret
		wantErr error
	}{
		{
			desc: "nil",
			s:    nil,
			want: nil,
		},
		{
			desc: "success",
			s:    secretGCPSAKStruct1,
			want: secretGCPSAKProto1,
		},
		{
			desc: "empty validation",
			s: func(s *inventory.Secret) *inventory.Secret {
				s = copier.Copy(s).(*inventory.Secret)
				s.Validation = inventory.SecretValidationResult{}
				return s
			}(secretGCPSAKStruct1),
			want: func(s *spb.Secret) *spb.Secret {
				s = copier.Copy(s).(*spb.Secret)
				s.Status = nil
				return s
			}(secretGCPSAKProto1),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := proto.SecretToProto(tc.s)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("SecretToProto(%v) returned error %v, want error %v", tc.s, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Fatalf("SecretToProto(%v) returned diff (-want +got):\n%s", tc.s, diff)
			}

			// No need to test the reverse conversion if the result is nil.
			if got == nil && tc.s != nil {
				return
			}

			// Test the reverse conversion for completeness.
			gotPB, err := proto.SecretToStruct(got)
			if err != nil {
				t.Fatalf("SecretToStruct(%v) returned error %v, want nil", got, err)
			}
			if diff := cmp.Diff(tc.s, gotPB, protocmp.Transform()); diff != "" {
				t.Fatalf("SecretToStruct(%v) returned diff (-want +got):\n%s", got, diff)
			}
		})
	}
}

// --- Proto to Struct

func TestSecretToStruct(t *testing.T) {
	copier := cpy.New(
		cpy.IgnoreAllUnexported(),
	)

	testCases := []struct {
		desc    string
		s       *spb.Secret
		want    *inventory.Secret
		wantErr error
	}{
		{
			desc: "nil",
			s:    nil,
			want: nil,
		},
		{
			desc: "success",
			s:    secretGCPSAKProto1,
			want: secretGCPSAKStruct1,
		},
		{
			desc: "empty validation",
			s: func(s *spb.Secret) *spb.Secret {
				s = copier.Copy(s).(*spb.Secret)
				s.Status = nil
				return s
			}(secretGCPSAKProto1),
			want: func(s *inventory.Secret) *inventory.Secret {
				s = copier.Copy(s).(*inventory.Secret)
				s.Validation = inventory.SecretValidationResult{}
				return s
			}(secretGCPSAKStruct1),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := proto.SecretToStruct(tc.s)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("SecretToStruct(%v) returned error %v, want error %v", tc.s, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Fatalf("SecretToStruct(%v) returned diff (-want +got):\n%s", tc.s, diff)
			}

			// No need to test the reverse conversion if the result is nil.
			if got == nil && tc.s != nil {
				return
			}

			// Test the reverse conversion for completeness.
			gotPB, err := proto.SecretToProto(got)
			if err != nil {
				t.Fatalf("SecretToProto(%v) returned error %v, want nil", got, err)
			}
			if diff := cmp.Diff(tc.s, gotPB, protocmp.Transform()); diff != "" {
				t.Fatalf("SecretToProto(%v) returned diff (-want +got):\n%s", got, diff)
			}
		})
	}
}
