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

package license_test

import (
	"context"
	"testing"

	depsdevpb "deps.dev/api/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/license"
	"github.com/google/osv-scalibr/enricher/license/fakeclient"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"google.golang.org/protobuf/proto"
)

func TestEnrich(t *testing.T) {
	cancelledContext, cancel := context.WithCancel(t.Context())
	cancel()

	copier := cpy.New(
		cpy.Func(proto.Clone),
		cpy.IgnoreAllUnexported(),
	)

	licenseMap := map[*depsdevpb.VersionKey][]string{
		{System: depsdevpb.System_NPM, Name: "express", Version: "4.17.1"}:                 {"MIT"},
		{System: depsdevpb.System_PYPI, Name: "requests", Version: "2.26.0"}:               {"Apache-2.0"},
		{System: depsdevpb.System_GO, Name: "github.com/gin-gonic/gin", Version: "v1.8.1"}: {"MIT"},
	}

	cli := fakeclient.New(licenseMap)
	e := license.NewWithClient(cli)

	tests := []struct {
		name     string
		packages []*extractor.Package
		//nolint:containedctx
		ctx          context.Context
		wantErr      error
		wantPackages []*extractor.Package
	}{
		{
			name:    "ctx_cancelled",
			ctx:     cancelledContext,
			wantErr: cmpopts.AnyError,
			packages: []*extractor.Package{
				{Name: "express", Version: "4.17.1", PURLType: purl.TypeNPM},
				{Name: "requests", Version: "2.26.0", PURLType: purl.TypePyPi},
				{Name: "github.com/gin-gonic/gin", Version: "1.8.1", PURLType: purl.TypeGolang},
			},
			wantPackages: []*extractor.Package{
				// No license data
				{Name: "express", Version: "4.17.1", PURLType: purl.TypeNPM},
				{Name: "requests", Version: "2.26.0", PURLType: purl.TypePyPi},
				{Name: "github.com/gin-gonic/gin", Version: "1.8.1", PURLType: purl.TypeGolang},
			},
		},
		{
			name: "simple_test",
			packages: []*extractor.Package{
				{Name: "express", Version: "4.17.1", PURLType: purl.TypeNPM},
				{Name: "requests", Version: "2.26.0", PURLType: purl.TypePyPi},
				{Name: "github.com/gin-gonic/gin", Version: "1.8.1", PURLType: purl.TypeGolang},
			},
			wantPackages: []*extractor.Package{
				{Name: "express", Version: "4.17.1", PURLType: purl.TypeNPM, Licenses: []string{"MIT"}},
				{Name: "requests", Version: "2.26.0", PURLType: purl.TypePyPi, Licenses: []string{"Apache-2.0"}},
				{Name: "github.com/gin-gonic/gin", Version: "1.8.1", PURLType: purl.TypeGolang, Licenses: []string{"MIT"}},
			},
		},
		{
			name: "not_covered_purl_type",
			packages: []*extractor.Package{
				{Name: "fzf", Version: "0.63.0", PURLType: purl.TypeBrew},
			},
			wantPackages: []*extractor.Package{
				// UNKNOWN license
				{Name: "fzf", Version: "0.63.0", PURLType: purl.TypeBrew, Licenses: []string{"UNKNOWN"}},
			},
		},
		{
			name: "unknown_package",
			packages: []*extractor.Package{
				{Name: "unknown", Version: "1.8.1", PURLType: purl.TypeGolang},
			},
			wantPackages: []*extractor.Package{
				// UNKNOWN license
				{Name: "unknown", Version: "1.8.1", PURLType: purl.TypeGolang, Licenses: []string{"UNKNOWN"}},
			},
		},
		{
			name: "not_covered_pkg_with_already_a_license",
			packages: []*extractor.Package{
				{Name: "fzf", Version: "0.63.0", PURLType: purl.TypeBrew, Licenses: []string{"Apache-2.0"}},
			},
			wantPackages: []*extractor.Package{
				{Name: "fzf", Version: "0.63.0", PURLType: purl.TypeBrew, Licenses: []string{"Apache-2.0"}},
			},
		},
		{
			name: "covered_pkg_with_already_a_license",
			packages: []*extractor.Package{
				{Name: "express", Version: "4.17.1", PURLType: purl.TypeNPM, Licenses: []string{"MIT"}},
			},
			wantPackages: []*extractor.Package{
				{Name: "express", Version: "4.17.1", PURLType: purl.TypeNPM, Licenses: []string{"MIT"}},
			},
		},
		{
			name: "covered_pkg_with_wrong_license",
			packages: []*extractor.Package{
				{Name: "express", Version: "4.17.1", PURLType: purl.TypeNPM, Licenses: []string{"Apache-2.0"}},
			},
			wantPackages: []*extractor.Package{
				{Name: "express", Version: "4.17.1", PURLType: purl.TypeNPM, Licenses: []string{"MIT"}},
			},
		},
		{
			name: "not_covered_purl_type_between_covered_pkgs",
			packages: []*extractor.Package{
				{Name: "express", Version: "4.17.1", PURLType: purl.TypeNPM},
				{Name: "github.com/gin-gonic/gin", Version: "1.8.1", PURLType: purl.TypeGolang},
				{Name: "fzf", Version: "0.63.0", PURLType: purl.TypeBrew},
				{Name: "requests", Version: "2.26.0", PURLType: purl.TypePyPi},
			},
			wantPackages: []*extractor.Package{
				{Name: "express", Version: "4.17.1", PURLType: purl.TypeNPM, Licenses: []string{"MIT"}},
				{Name: "github.com/gin-gonic/gin", Version: "1.8.1", PURLType: purl.TypeGolang, Licenses: []string{"MIT"}},
				{Name: "fzf", Version: "0.63.0", PURLType: purl.TypeBrew, Licenses: []string{"UNKNOWN"}},
				{Name: "requests", Version: "2.26.0", PURLType: purl.TypePyPi, Licenses: []string{"Apache-2.0"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ctx == nil {
				tt.ctx = t.Context()
			}

			var input *enricher.ScanInput

			packages := copier.Copy(tt.packages).([]*extractor.Package)
			inv := &inventory.Inventory{Packages: packages}

			err := e.Enrich(tt.ctx, input, inv)
			if !cmp.Equal(tt.wantErr, err, cmpopts.EquateErrors()) {
				t.Fatalf("Enrich(%v) error: %v, want %v", tt.packages, err, tt.wantErr)
			}

			want := &inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(want, inv); diff != "" {
				t.Errorf("Enrich(%v): unexpected diff (-want +got): %v", tt.packages, diff)
			}
		})
	}
}
