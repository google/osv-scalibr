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
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/binary/proto"
	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
)

var (
	idToPkg = map[string]*extractor.Package{
		"1": purlDPKGAnnotationPackage,
	}
	pkgToID = func() map[*extractor.Package]string {
		m := make(map[*extractor.Package]string)
		for id, pkg := range idToPkg {
			m[pkg] = id
		}
		return m
	}()

	pkgVulnStruct1 = &inventory.PackageVuln{
		Vulnerability: &osvpb.Vulnerability{},
		Package:       purlDPKGAnnotationPackage,
		Plugins:       []string{"cve/cve-1234-finder", "cve/cve-1234-enricher"},
		ExploitabilitySignals: []*vex.FindingExploitabilitySignal{{
			Plugin:        "some-plugin",
			Justification: vex.ComponentNotPresent,
		}},
	}
	pkgVulnProto1 = &spb.PackageVuln{
		Vuln:      &osvpb.Vulnerability{},
		PackageId: "1",
		Plugins:   []string{"cve/cve-1234-finder", "cve/cve-1234-enricher"},
		ExploitabilitySignals: []*spb.FindingExploitabilitySignal{
			{
				Plugin:        "some-plugin",
				Justification: spb.VexJustification_COMPONENT_NOT_PRESENT,
			},
		},
	}
)

func TestPackageVulnSetup(t *testing.T) {
	if len(pkgToID) != len(idToPkg) {
		t.Fatalf("pkgToID and idToPkg have different lengths: %d != %d", len(pkgToID), len(idToPkg))
	}
	for pkg, id := range pkgToID {
		otherPkg, ok := idToPkg[id]
		if !ok {
			t.Fatalf("package with ID %q not found in idToPkg map", id)
		}
		if pkg != otherPkg {
			t.Fatalf("package with ID %q has different pointer value %v", id, otherPkg)
		}
	}
}

func TestPackageVulnToProto(t *testing.T) {
	copier := cpy.New(
		cpy.IgnoreAllUnexported(),
	)

	testCases := []struct {
		desc    string
		pkgVuln *inventory.PackageVuln
		pkgToID map[*extractor.Package]string
		want    *spb.PackageVuln
		wantErr error
	}{
		{
			desc:    "nil",
			pkgVuln: nil,
			want:    nil,
		},
		{
			desc:    "success",
			pkgVuln: pkgVulnStruct1,
			pkgToID: pkgToID,
			want:    pkgVulnProto1,
		},
		{
			desc: "missing package",
			pkgVuln: func(p *inventory.PackageVuln) *inventory.PackageVuln {
				p = copier.Copy(p).(*inventory.PackageVuln)
				p.Package = nil
				return p
			}(pkgVulnStruct1),
			pkgToID: pkgToID,
			want:    nil,
			wantErr: proto.ErrPackageMissing,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := proto.PackageVulnToProto(tc.pkgVuln, tc.pkgToID)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("PackageVulnToProto(%+v, %+v) returned error %v, want error %v", tc.pkgVuln, tc.pkgToID, err, tc.wantErr)
			}

			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Fatalf("PackageVulnToProto(%+v, %+v) returned diff (-want +got):\n%s", tc.pkgVuln, tc.pkgToID, diff)
			}

			// No need to test the reverse conversion if the result is nil.
			if got == nil {
				return
			}

			idToPkg := map[string]*extractor.Package{}
			for pkg, id := range tc.pkgToID {
				idToPkg[id] = pkg
			}

			// Test the reverse conversion for completeness.
			gotPB, err := proto.PackageVulnToStruct(got, idToPkg)
			if err != nil {
				t.Fatalf("PackageVulnToStruct(%v, %v) returned error %v, want nil", got, idToPkg, err)
			}
			if diff := cmp.Diff(tc.pkgVuln, gotPB, protocmp.Transform()); diff != "" {
				t.Fatalf("PackageVulnToStruct(%v, %v) returned diff (-want +got):\n%s", got, idToPkg, diff)
			}
		})
	}
}

func TestPackageVulnToStruct(t *testing.T) {
	copier := cpy.New(
		cpy.IgnoreAllUnexported(),
	)

	testCases := []struct {
		desc    string
		pkgVuln *spb.PackageVuln
		idToPkg map[string]*extractor.Package
		want    *inventory.PackageVuln
		wantErr error
	}{
		{
			desc:    "nil",
			pkgVuln: nil,
			want:    nil,
		},
		{
			desc:    "success",
			pkgVuln: pkgVulnProto1,
			idToPkg: idToPkg,
			want:    pkgVulnStruct1,
		},
		{
			desc: "missing package ID",
			pkgVuln: func(p *spb.PackageVuln) *spb.PackageVuln {
				p = copier.Copy(p).(*spb.PackageVuln)
				p.PackageId = ""
				return p
			}(pkgVulnProto1),
			idToPkg: idToPkg,
			want:    nil,
			wantErr: proto.ErrPackageMissing,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := proto.PackageVulnToStruct(tc.pkgVuln, tc.idToPkg)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("PackageVulnToStruct(%v, %v) returned error %v, want error %v", tc.pkgVuln, tc.idToPkg, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Fatalf("PackageVulnToStruct(%v, %v) returned diff (-want +got):\n%s", tc.pkgVuln, tc.idToPkg, diff)
			}

			// No need to test the reverse conversion if the result is nil.
			if got == nil {
				return
			}

			pkgToID := map[*extractor.Package]string{}
			for id, pkg := range tc.idToPkg {
				pkgToID[pkg] = id
			}

			// Test the reverse conversion for completeness.
			gotPB, err := proto.PackageVulnToProto(got, pkgToID)
			if err != nil {
				t.Fatalf("PackageVulnToProto(%v, %v) returned error %v, want nil", got, pkgToID, err)
			}
			if diff := cmp.Diff(tc.pkgVuln, gotPB, protocmp.Transform()); diff != "" {
				t.Fatalf("PackageVulnToProto(%v, %v) returned diff (-want +got):\n%s", got, pkgToID, diff)
			}
		})
	}
}
