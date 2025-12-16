package osvlocal_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvlocal"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestEnrich(t *testing.T) {
	tests := []struct {
		name         string
		packageVulns []*inventory.PackageVuln
		packages     []*extractor.Package
		//nolint:containedctx
		ctx              context.Context
		wantErr          error
		wantPackageVulns []*inventory.PackageVuln
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ctx == nil {
				tt.ctx = context.Background()
			}

			e := osvlocal.NewDefault()

			var input *enricher.ScanInput

			if tt.packageVulns == nil {
				tt.packageVulns = []*inventory.PackageVuln{}
			}

			inv := &inventory.Inventory{
				PackageVulns: tt.packageVulns,
				Packages:     tt.packages,
			}

			err := e.Enrich(tt.ctx, input, inv)
			if !cmp.Equal(tt.wantErr, err, cmpopts.EquateErrors()) {
				t.Fatalf("Enrich(%v) error: %v, want %v", tt.packages, err, tt.wantErr)
			}

			want := &inventory.Inventory{
				PackageVulns: tt.wantPackageVulns,
				Packages:     tt.packages,
			}

			sortPkgVulns := cmpopts.SortSlices(func(a, b *inventory.PackageVuln) bool {
				if a.Vulnerability.Id != b.Vulnerability.Id {
					return a.Vulnerability.Id < b.Vulnerability.Id
				}
				return a.Package.Name < b.Package.Name
			})

			diff := cmp.Diff(
				want, inv,
				sortPkgVulns,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool { return a < b }),
			)

			if diff != "" {
				t.Errorf("Enrich(%v): unexpected diff (-want +got): %v", tt.packages, diff)
			}
		})
	}
}
