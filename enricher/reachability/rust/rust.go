// Package rust provides an enricher that adds reachability information to Rust packages.
package rust

import (
	"bytes"
	"context"
	"debug/dwarf"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/reachability/rust/ar"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvdev"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/ianlancetaylor/demangle"
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

// Enricher enriches inventory's package vulnerability with reachability info
type Enricher struct{}

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
func New() enricher.Enricher {
	return &Enricher{}
}

// Enrich enriches the inventory with reachability information.
func (e *Enricher) Enrich(ctx context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	// Temp directory for the cargo build artifacts and easy clean up
	targetDir, err := os.MkdirTemp("", "rust-reachability-*")
	if err != nil {
		return fmt.Errorf("failed to create temp target dir: %w", err)
	}
	defer os.RemoveAll(targetDir)

	// Build the project and get the binary artifacts
	binaryPaths, err := rustBuildSource(ctx, input.ScanRoot.Path, targetDir)
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
			buf, err := extractRlibArchive(path)
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
		calls, err := functionsFromDWARF(readAt)
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

func rustBuildSource(ctx context.Context, path string, targetDir string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "cargo", "build", "--workspace", "--all-targets", "--release", "--target-dir", targetDir)
	cmd.Env = append(cmd.Environ(), rustFlagsEnv)
	cmd.Dir = path
	if errors.Is(cmd.Err, exec.ErrDot) {
		cmd.Err = nil
	}

	stdoutBuffer := bytes.Buffer{}
	stderrBuffer := bytes.Buffer{}
	cmd.Stdout = &stdoutBuffer
	cmd.Stderr = &stderrBuffer

	log.Infof("Begin building rust/cargo project %v", path)

	if err := cmd.Run(); err != nil {
		log.Errorf("cargo stdout:\n%s", stdoutBuffer.String())
		log.Errorf("cargo stderr:\n%s", stderrBuffer.String())

		return nil, fmt.Errorf("failed to run `%v`: %w", cmd.String(), err)
	}

	outputDir := filepath.Join(targetDir, "release")
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read \"%s\" dir: %w", outputDir, err)
	}

	resultBinaryPaths := []string{}
	for _, de := range entries {
		// We only want .d files, which is generated for each output binary from cargo
		// These files contains a string to the full path of output binary/library file.
		// This is a reasonably reliable way to identify the output in a cross-platform way.
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".d") {
			continue
		}

		file, err := os.ReadFile(filepath.Join(outputDir, de.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to read \"%s\": %w", filepath.Join(outputDir, de.Name()), err)
		}

		fileSplit := strings.Split(string(file), ": ")
		if len(fileSplit) != 2 {
			return nil, errors.New("file path contains ': ', which is unsupported")
		}
		resultBinaryPaths = append(resultBinaryPaths, fileSplit[0])
	}

	return resultBinaryPaths, nil
}

// extractRlibArchive return the file path to a temporary ELF Object file extracted from the given rlib.
//
// It is the callers responsibility to remove the temporary file
func extractRlibArchive(rlibPath string) (bytes.Buffer, error) {
	buf := bytes.Buffer{}
	rlibFile, err := os.Open(rlibPath)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("failed to open .rlib file '%s': %w", rlibPath, err)
	}

	reader, err := ar.NewReader(rlibFile)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf(".rlib file '%s' is not valid ar archive: %w", rlibPath, err)
	}
	for {
		header, err := reader.Next()
		if err != nil {
			log.Errorf("file reader error: %v", err)
		}
		if header.Name == "//" { // "//" is used in GNU ar format as a store for long file names
			fileBuf := bytes.Buffer{}
			_, err = io.Copy(&fileBuf, reader)
			if err != nil {
				return bytes.Buffer{}, fmt.Errorf("failed to read // store in ar archive: %w", err)
			}

			filename := strings.TrimSpace(fileBuf.String())

			// There should only be one file (since we set codegen-units=1)
			if !strings.HasSuffix(filename, rustLibExtension) {
				log.Warnf("rlib archive contents were unexpected: %s\n", filename)
			}
		}
		// /0 indicates the first file mentioned in the "//" store
		if header.Name == "/0" || strings.HasSuffix(header.Name, rustLibExtension) {
			break
		}
	}
	_, err = io.Copy(&buf, reader)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("failed to read from archive '%s': %w", rlibPath, err)
	}

	return buf, nil
}

func functionsFromDWARF(readAt io.ReaderAt) (map[string]struct{}, error) {
	output := map[string]struct{}{}
	file, err := elf.NewFile(readAt)
	if err != nil {
		return nil, fmt.Errorf("failed to read binary: %w", err)
	}
	dwarfData, err := file.DWARF()
	if err != nil {
		return nil, fmt.Errorf("failed to extract debug symbols from binary: %w", err)
	}
	entryReader := dwarfData.Reader()

	for {
		entry, err := entryReader.Next()
		if errors.Is(err, io.EOF) || entry == nil {
			// We've reached the end of DWARF entries
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error parsing binary DWARF data: %w", err)
		}

		// We only care about contents in functions
		if entry.Tag != dwarf.TagSubprogram {
			continue
		}
		// Go through fields
		for _, field := range entry.Field {
			// We only care about linkage names (including function names)
			if field.Attr != dwarf.AttrLinkageName {
				continue
			}

			val, err := demangle.ToString(field.Val.(string), demangle.NoClones)
			if err != nil {
				// most likely not a rust function, so just ignore it
				continue
			}

			val = cleanRustFunctionSymbols(val)
			output[val] = struct{}{}
		}
	}

	return output, nil
}

// cleanRustFunctionSymbols takes in demanged rust symbols and makes them fit format of
// the common function level advisory information
func cleanRustFunctionSymbols(val string) string {
	// Used to remove generics from functions and types as they are not included in function calls
	// in advisories:
	// E.g.: `smallvec::SmallVec<A>::new` => `smallvec::SmallVec::new`
	//
	// Usage: antiGenericRegex.ReplaceAllString(val, "")
	antiGenericRegex := regexp.MustCompile(`<[\w,]+>`)
	val = antiGenericRegex.ReplaceAllString(val, "")

	// Used to remove fully qualified trait implementation indicators from the function type,
	// since those are generally not included in advisory:
	// E.g.: `<libflate::gzip::MultiDecoder as std::io::Read>::read` => `libflate::gzip::MultiDecoder::read`
	antiTraitImplRegex := regexp.MustCompile(`<(.*) as .*>`)
	val = antiTraitImplRegex.ReplaceAllString(val, "$1")

	return val
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
