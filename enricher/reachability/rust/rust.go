// Package rust provides an enricher that adds reachability information to Rust packages.
package rust

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvdev"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the name of the rust reachability enricher.
	Name = "reachability/rust"

	// rustFlagsEnv defines the flags that are required for effective source analysis:
	// - opt-level=3 (Use the highest optimisation level (default with --release))
	// - debuginfo=1 (Include DWARF debug info which is extracted to find which funcs are called)
	// - embed-bitcode=yes (Required to enable LTO)
	// - lto (Enable full link time optimisation, this allows unused dynamic dispatch calls to be optimised out)
	// - codegen-units=1 (Build everything in one codegen unit, increases build time but enables more optimisations
	//                  and make libraries only generate one object file)
	rustFlagsEnv     = "RUSTFLAGS=-C opt-level=3 -C debuginfo=1 -C embed-bitcode=yes -C lto -C codegen-units=1 -C strip=none"
	rustLibExtension = ".rcgu.o/"
)

// Regex used for fuzzy funcion matching
var antiLeadingSpecCharRegex = regexp.MustCompile(`\W*(.+)`)

// ErrNoRustToolchain is returned when the cargo is not found in the system.
var ErrNoRustToolchain = errors.New("no Rust toolchain found")

// Enricher enriches inventory's package vulnerability with reachability info
type Enricher struct {
	client Client
}

// Name of the enricher.
func (*Enricher) Name() string { return Name }

// Version of enricher.
func (*Enricher) Version() int { return 0 }

// Requirements of rust reachability enricher.
func (*Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		DirectFS:      true,
		Network:       plugin.NetworkOnline,
		OS:            plugin.OSLinux,
		RunningSystem: true,
	}
}

// RequiredPlugins returns a list of Plugins that need to be enabled for this Enricher to work.
func (*Enricher) RequiredPlugins() []string {
	return []string{osvdev.Name}
}

// New returns a new rust reachability enricher.
func New(cfg *cpb.PluginConfig) enricher.Enricher {
	return &Enricher{client: &realClient{}}
}

// NewWithClient returns a new rust reachability enricher with custom client.
func NewWithClient(c Client) enricher.Enricher {
	return &Enricher{client: c}
}

// Enrich enriches the inventory with reachability information.
func (e *Enricher) Enrich(ctx context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	if !e.client.RustToolchainAvailable(ctx) {
		return ErrNoRustToolchain
	}

	// Temp directory for the cargo build artifacts and easy clean up
	targetDir, err := os.MkdirTemp("", "rust-reachability-*")
	if err != nil {
		return fmt.Errorf("failed to create temp target dir: %w", err)
	}
	defer os.RemoveAll(targetDir)

	// Build the project and get the binary artifacts
	binaryPaths, err := e.client.BuildSource(ctx, input.ScanRoot.Path, targetDir)
	if err != nil {
		return fmt.Errorf("failed to build cargo/rust project from source: %w", err)
	}

	// This map stores 3 states for each vuln ID
	// - There is function level vuln info, but it **wasn't** called   (false)
	// - There is function level vuln info, and it **is** called    (true)
	// - There is **no** functional level vuln info, so we don't know whether it is called (doesn't exist)
	isCalledVulnMap := map[string]bool{}

	// For each binary artifact, extract the DWARF data to find all called functions, do the enriching, etc
	for _, path := range binaryPaths {
		var readAt io.ReaderAt
		if strings.HasSuffix(path, ".rlib") {
			// Is a library, so need an extra step to extract the object binary file before passing to parseDWARFData
			buf, err := e.client.ExtractRlibArchive(path)
			if err != nil {
				log.Errorf("failed to extract rlib archive '%s': %s", path, err)
				continue
			}
			readAt = bytes.NewReader(buf.Bytes())
		} else {
			f, err := os.Open(path)
			if err != nil {
				log.Errorf("failed to read binary '%s': %s", path, err)
				continue
			}
			// This is fine to defer til the end of the function as there's
			// generally single digit number of binaries in a project
			defer f.Close()
			readAt = f
		}

		// Extract called functions
		calls, err := e.client.FunctionsFromDWARF(readAt)
		if err != nil {
			log.Errorf("failed to extract functions from '%s': %s", path, err)
			continue
		}

		for _, pv := range inv.PackageVulns {
			v := pv.Vulnerability
			for _, a := range v.GetAffected() {
				// Example of RUSTSEC function level information:
				//
				// "affects": {
				//     "os": [],
				//     "functions": [
				//         "smallvec::SmallVec::grow"
				//     ],
				//     "arch": []
				// }

				ecosystemSpec := a.EcosystemSpecific.AsMap()
				ecosystemAffects, ok := ecosystemSpec["affects"].(map[string]any)
				if !ok {
					continue
				}
				affectedFunctions, ok := ecosystemAffects["functions"].([]any)
				if !ok {
					continue
				}
				for _, f := range affectedFunctions {
					if funcName, ok := f.(string); ok {
						_, called := calls[funcName]
						// Only try fuzzy match if full func path doesn't match anything
						if !called {
							called = fuzzyMatchFuncCall(funcName, calls)
						}
						// Once one advisory marks this vuln as called, always mark as called
						isCalledVulnMap[v.Id] = isCalledVulnMap[v.Id] || called
					}
				}
			}
		}

		// Enrich package vulns according to isCalledVulnMap states:
		// - There is function level vuln info, but it **wasn't** called (false) -> Add VEX ExploitabilitySignal
		// - There is function level vuln info, and it **is** called (true) -> Do not add signal
		// - There is **no** functional level vuln info, so we don't know whether it is called -> Do not add signal.
		for _, pv := range inv.PackageVulns {
			if called, hasFuncInfo := isCalledVulnMap[pv.Vulnerability.Id]; hasFuncInfo {
				if !called {
					pv.ExploitabilitySignals = append(pv.ExploitabilitySignals, &vex.FindingExploitabilitySignal{
						Plugin:        Name,
						Justification: vex.VulnerableCodeNotInExecutePath,
					})

					log.Debugf("Added a unreachable signal to vulnerability '%s'", pv.Vulnerability.Id)
				}
			}
		}
	}

	return nil
}

func fuzzyMatchFuncCall(target string, calls map[string]struct{}) bool {
	// Target is from registry, in the form `crate_name::<ignore in-betweens>::func_name`
	targetSegments := strings.Split(target, "::")
	targetCrate := targetSegments[0]
	targetFunc := targetSegments[len(targetSegments)-1]

	// To fuzzy match the func calls from binary:
	// 1. Must match crate name
	// 2. Starting from the back of the path, try to match the func_name
	for call := range calls {
		segments := strings.Split(call, "::")

		// Removes leading special characters in crate name
		segments[0] = antiLeadingSpecCharRegex.ReplaceAllString(segments[0], "$1")
		if segments[0] != targetCrate {
			continue
		}

		for i := len(segments) - 1; i > 0; i-- {
			if segments[i] == targetFunc {
				return true
			}
		}
	}
	return false
}
