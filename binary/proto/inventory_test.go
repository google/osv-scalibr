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
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
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
				PackageVulns: []*inventory.PackageVuln{
					pkgVulnStruct1,
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
				PackageVulns: []*pb.PackageVuln{
					pkgVulnProto1,
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
			opts := append([]cmp.Option{
				protocmp.Transform(),
				protocmp.IgnoreFields(&pb.PackageVuln{}, "package_id"),
				cmpopts.EquateEmpty(),
			}, pkgOpts...)
			if diff := cmp.Diff(tc.want, got, opts...); diff != "" {
				t.Errorf("InventoryToProto(%v) returned diff (-want +got):\n%s", tc.inv, diff)
			}

			// Test the reverse conversion for completeness.
			gotInv := proto.InventoryToStruct(got)
			opts = []cmp.Option{
				protocmp.Transform(),
				cmpopts.IgnoreFields(extractor.LayerMetadata{}, "ParentContainer"),
			}
			if diff := cmp.Diff(tc.inv, gotInv, opts...); diff != "" {
				t.Errorf("InventoryToStruct(%v) returned diff (-want +got):\n%s", gotInv, diff)
			}
		})
	}
}

// We do it in a separate test because we don't want to test the reverse operation.
func TestInventoryToProtoInvalidPackage(t *testing.T) {
	testCases := []struct {
		desc    string
		inv     *inventory.Inventory
		want    *pb.Inventory
		wantErr error
	}{
		{
			desc: "missing_package",
			inv: &inventory.Inventory{
				PackageVulns: []*inventory.PackageVuln{
					pkgVulnStruct1,
				},
			},
			wantErr: cmpopts.AnyError,
			want:    nil,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := proto.InventoryToProto(tc.inv)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("InventoryToProto() error mismatch (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tc.want, got, pkgOpts...); diff != "" {
				t.Errorf("InventoryToProto(%v) returned diff (-want +got):\n%s", tc.inv, diff)
			}
		})
	}
}

func TestInventoryToStruct(t *testing.T) {
	pkgWithIDProto :=
		&pb.Package{
			Id:        "1234567890",
			Name:      "software",
			Version:   "1.0.0",
			Locations: []string{"/file1"},
			Plugins:   []string{"os/dpkg"},
		}
	pkgStruct :=
		&extractor.Package{
			Name:      "software",
			Version:   "1.0.0",
			Locations: []string{"/file1"},
			Plugins:   []string{"os/dpkg"},
		}
	pkgVulnProto := &pb.PackageVuln{
		Vuln:      &osvpb.Vulnerability{Id: "GHSA-1"},
		PackageId: pkgWithIDProto.Id,
		Plugins:   []string{"plugin1"},
	}
	pkgVulnStruct := &inventory.PackageVuln{
		Vulnerability: &osvpb.Vulnerability{Id: "GHSA-1"},
		Package:       pkgStruct,
		Plugins:       []string{"plugin1"},
	}
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
					pkgWithIDProto,
				},
				PackageVulns: []*pb.PackageVuln{
					pkgVulnProto,
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
					pkgStruct,
				},
				PackageVulns: []*inventory.PackageVuln{
					pkgVulnStruct,
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
			opts := []cmp.Option{
				protocmp.Transform(),
				cmpopts.IgnoreFields(extractor.LayerMetadata{}, "ParentContainer"),
				cmpopts.EquateEmpty(),
			}
			if diff := cmp.Diff(tc.want, got, opts...); diff != "" {
				t.Errorf("InventoryToStruct(%v) returned diff (-want +got):\n%s", tc.inv, diff)
			}

			// Test the reverse conversion for completeness.
			gotPB, err := proto.InventoryToProto(got)
			if err != nil {
				t.Fatalf("InventoryToProto(%v) returned error %v, want nil", got, err)
			}
			revOpts := append([]cmp.Option{
				protocmp.Transform(),
				protocmp.IgnoreFields(&pb.PackageVuln{}, "package_id"),
				cmpopts.EquateEmpty(),
			}, pkgOpts...)
			if diff := cmp.Diff(tc.inv, gotPB, revOpts...); diff != "" {
				t.Errorf("InventoryToProto(%v) returned diff (-want +got):\n%s", got, diff)
			}
		})
	}
}

// We do it in a separate test because the conversion is lossy and we don't want
// to test the reverse operation.
func TestInventoryToStructInvalidPkgVuln(t *testing.T) {
	testCases := []struct {
		desc string
		inv  *pb.Inventory
		want *inventory.Inventory
	}{
		{
			desc: "package_without_id",
			inv: &pb.Inventory{
				Packages:     []*pb.Package{{Name: "no_id_pkg"}},
				PackageVulns: []*pb.PackageVuln{{PackageId: "some_id"}},
			},
			want: &inventory.Inventory{
				Packages: []*extractor.Package{{Name: "no_id_pkg"}},
			},
		},
		{
			desc: "packages_with_duplicate_id",
			inv: &pb.Inventory{
				Packages:     []*pb.Package{{Name: "pkg1", Id: "pkg"}, {Name: "pkg2", Id: "pkg"}},
				PackageVulns: []*pb.PackageVuln{{PackageId: "pkg"}},
			},
			want: &inventory.Inventory{
				Packages:     []*extractor.Package{{Name: "pkg1"}, {Name: "pkg2"}},
				PackageVulns: []*inventory.PackageVuln{{Package: &extractor.Package{Name: "pkg1"}}},
			},
		},
		{
			desc: "pkgvuln_with_no_packages",
			inv: &pb.Inventory{
				PackageVulns: []*pb.PackageVuln{{PackageId: "some_id"}},
			},
			want: &inventory.Inventory{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := proto.InventoryToStruct(tc.inv)
			if diff := cmp.Diff(tc.want, got, cmpopts.IgnoreFields(extractor.LayerMetadata{}, "ParentContainer"), protocmp.Transform()); diff != "" {
				t.Fatalf("InventoryToStruct(%v) returned diff (-want +got):\n%s", tc.inv, diff)
			}
		})
	}
}
