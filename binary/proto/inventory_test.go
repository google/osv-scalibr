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

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/binary/proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func TestInventoryToProto(t *testing.T) {
	testCases := []struct {
		desc    string
		inv     *inventory.Inventory
		want    *pb.Inventory
		wantErr error
	}{
		{
			desc: "nil",
			inv:  nil,
			want: nil,
		},
		{
			desc: "empty",
			inv:  &inventory.Inventory{},
			want: &pb.Inventory{},
		},
		{
			desc: "success",
			inv: &inventory.Inventory{
				Packages: []*extractor.Package{
					purlDPKGAnnotationPackage,
					pkgWithLayerStruct,
				},
				GenericFindings: []*inventory.GenericFinding{
					genericFindingStruct1,
				},
				Secrets: []*inventory.Secret{
					secretGCPSAKStruct1,
				},
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					cimStructForTest,
				},
			},
			want: &pb.Inventory{
				Packages: []*pb.Package{
					purlDPKGAnnotationPackageProto,
					pkgWithLayerProto,
				},
				GenericFindings: []*pb.GenericFinding{
					genericFindingProto1,
				},
				Secrets: []*pb.Secret{
					secretGCPSAKProto1,
				},
				ContainerImageMetadata: []*pb.ContainerImageMetadata{
					cimProtoForTest,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := proto.InventoryToProto(tc.inv)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("InventoryToProto(%v) returned error %v, want error %v", tc.inv, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got, protocmp.Transform(), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("InventoryToProto(%v) returned diff (-want +got):\n%s", tc.inv, diff)
			}

			// Test the reverse conversion for completeness.
			gotInv := proto.InventoryToStruct(got)
			if diff := cmp.Diff(tc.inv, gotInv, cmpopts.IgnoreFields(extractor.LayerMetadata{}, "ParentContainer")); diff != "" {
				t.Errorf("InventoryToStruct(%v) returned diff (-want +got):\n%s", got, diff)
			}
		})
	}
}

func TestInventoryToStruct(t *testing.T) {
	testCases := []struct {
		desc string
		inv  *pb.Inventory
		want *inventory.Inventory
	}{
		{
			desc: "nil",
			inv:  nil,
			want: nil,
		},
		{
			desc: "empty",
			inv:  &pb.Inventory{},
			want: &inventory.Inventory{},
		},
		{
			desc: "success",
			inv: &pb.Inventory{
				Packages: []*pb.Package{
					purlDPKGAnnotationPackageProto,
					pkgWithLayerProto,
				},
				GenericFindings: []*pb.GenericFinding{
					genericFindingProto1,
				},
				Secrets: []*pb.Secret{
					secretGCPSAKProto1,
				},
				ContainerImageMetadata: []*pb.ContainerImageMetadata{
					cimProtoForTest,
				},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{
					purlDPKGAnnotationPackage,
					pkgWithLayerStruct,
				},
				GenericFindings: []*inventory.GenericFinding{
					genericFindingStruct1,
				},
				Secrets: []*inventory.Secret{
					secretGCPSAKStruct1,
				},
				ContainerImageMetadata: []*extractor.ContainerImageMetadata{
					cimStructForTest,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := proto.InventoryToStruct(tc.inv)
			if diff := cmp.Diff(tc.want, got, cmpopts.IgnoreFields(extractor.LayerMetadata{}, "ParentContainer")); diff != "" {
				t.Errorf("InventoryToStruct(%v) returned diff (-want +got):\n%s", tc.inv, diff)
			}

			// Test the reverse conversion for completeness.
			gotPB, err := proto.InventoryToProto(got)
			if err != nil {
				t.Fatalf("InventoryToProto(%v) returned error %v, want nil", got, err)
			}
			if diff := cmp.Diff(tc.inv, gotPB, protocmp.Transform(), cmpopts.EquateEmpty()); diff != "" {
				t.Fatalf("InventoryToProto(%v) returned diff (-want +got):\n%s", got, diff)
			}
		})
	}
}
