package osvlocal

import (
	"context"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/plugin"
	scalibrversion "github.com/google/osv-scalibr/version"
)

const (
	// Name is the unique name of this Enricher.
	Name    = "vulnmatch/osvlocal"
	version = 1
)

var _ enricher.Enricher = &Enricher{}

// Enricher uses the OSV.dev zip databases to find vulnerabilities in the inventory packages
type Enricher struct {
	zippedDBRemoteHost string
}

// NewDefault creates a new Enricher with the default configuration
func NewDefault() enricher.Enricher {
	return &Enricher{"https://osv-vulnerabilities.storage.googleapis.com"}
}

func newForTesting(zippedDBRemoteHost string) enricher.Enricher {
	return &Enricher{zippedDBRemoteHost}
}

// Name of the Enricher.
func (Enricher) Name() string {
	return Name
}

// Version of the Enricher.
func (Enricher) Version() int {
	return version
}

// Requirements of the Enricher.
// Needs network access so it can download databases.
func (Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		Network: plugin.NetworkOnline,
	}
}

// RequiredPlugins returns the plugins that are required to be enabled for this
// Enricher to run. While it works on the results of other extractors,
// the Enricher itself can run independently.
func (Enricher) RequiredPlugins() []string {
	return []string{}
}

func (e *Enricher) Enrich(ctx context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	dbs, err := newlocalMatcher(
		"",
		"osv-scanner_scan/"+scalibrversion.ScannerVersion,
		true,
		e.zippedDBRemoteHost,
	)

	if err != nil {
		return err
	}

	for _, pkg := range inv.Packages {
		vulns, err := dbs.MatchVulnerabilities(ctx, pkg, inv.Packages)

		if err != nil {
			return err
		}

		for _, vuln := range vulns {
			inv.PackageVulns = append(inv.PackageVulns, &inventory.PackageVuln{
				Vulnerability:         vuln,
				Package:               pkg,
				ExploitabilitySignals: vex.FindingVEXFromPackageVEX(vuln.Id, pkg.ExploitabilitySignals),
				Plugins:               []string{Name},
			})
		}
	}

	return nil
}
