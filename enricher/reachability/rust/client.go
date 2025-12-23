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

package rust

import (
	"bytes"
	"context"
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/google/osv-scalibr/enricher/reachability/rust/ar"
	"github.com/google/osv-scalibr/log"
	"github.com/ianlancetaylor/demangle"
)

type realClient struct{}

const (
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

// BuildSource builds the rust project and returns a list filepaths containing the binary files
func (*realClient) BuildSource(ctx context.Context, path string, targetDir string) ([]string, error) {
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

	var resultBinaryPaths []string
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

// ExtractRlibArchive return the file path to a temporary ELF Object file extracted from the given rlib.
// It is the callers responsibility to remove the temporary file
func (*realClient) ExtractRlibArchive(rlibPath string) (*bytes.Buffer, error) {
	buf := &bytes.Buffer{}
	rlibFile, err := os.Open(rlibPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open .rlib file '%s': %w", rlibPath, err)
	}

	reader, err := ar.NewReader(rlibFile)
	if err != nil {
		return nil, fmt.Errorf(".rlib file '%s' is not valid ar archive: %w", rlibPath, err)
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
				return nil, fmt.Errorf("failed to read // store in ar archive: %w", err)
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
	_, err = io.Copy(buf, reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read from archive '%s': %w", rlibPath, err)
	}

	return buf, nil
}

// FunctionsFromDWARF extracts function symbols from file provided
func (*realClient) FunctionsFromDWARF(readAt io.ReaderAt) (map[string]struct{}, error) {
	output := map[string]struct{}{}
	dwarfData, err := readDWARF(readAt)
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

// RustToolchainAvailable checks if the rust toolchain is available
func (*realClient) RustToolchainAvailable(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "cargo", "--version")
	_, err := cmd.Output()

	return err == nil
}

// readDWARF reads DWARF data from input binary file based on the OS.
func readDWARF(readAt io.ReaderAt) (*dwarf.Data, error) {
	switch runtime.GOOS {
	case "linux":
		file, err := elf.NewFile(readAt)
		if err != nil {
			return nil, fmt.Errorf("failed to read binary, elf.NewFile: %w", err)
		}
		return file.DWARF()
	case "darwin":
		file, err := macho.NewFile(readAt)
		if err != nil {
			return nil, fmt.Errorf("failed to read binary, macho.NewFile: %w", err)
		}
		return file.DWARF()
	case "windows":
		file, err := pe.NewFile(readAt)
		if err != nil {
			return nil, fmt.Errorf("failed to read binary, pe.NewFile: %w", err)
		}
		return file.DWARF()
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}
