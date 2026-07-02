// Copyright 2026 Google LLC
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
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/enricher/reachability/rust/ar"
	"github.com/google/osv-scalibr/log"
	"github.com/ianlancetaylor/demangle"
)

type realClient struct{}

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
	defer rlibFile.Close()

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
	var dwarfData *dwarf.Data

	// 1. Try ELF (Linux)
	if elfFile, err := elf.NewFile(readAt); err == nil {
		dwarfData, err = elfFile.DWARF()
		if err != nil {
			return nil, fmt.Errorf("failed to extract debug symbols from elf binary: %w", err)
		}
	} else {
		// 2. Try Mach-O Thin (macOS)
		if machoFile, err := macho.NewFile(readAt); err == nil {
			dwarfData, err = machoFile.DWARF()
			if err != nil {
				return nil, fmt.Errorf("failed to extract debug symbols from macho binary: %w", err)
			}
		} else {
			// 3. Try Mach-O Fat (macOS Universal)
			if fatFile, err := macho.NewFatFile(readAt); err == nil {
				// Iterate through architectures to find one with DWARF data
				found := false
				for _, arch := range fatFile.Arches {
					if arch.File != nil {
						if d, err := arch.File.DWARF(); err == nil {
							dwarfData = d
							found = true
							break
						}
					}
				}
				if !found {
					return nil, errors.New("failed to extract debug symbols from fat macho binary (no valid arch found)")
				}
			} else {
				// 4. Unknown format
				return nil, errors.New("failed to read binary: unsupported format (not ELF, Mach-O thin or fat)")
			}
		}
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

			valStr, ok := field.Val.(string)
			if !ok {
				continue
			}

			val, err := demangle.ToString(valStr, demangle.NoClones)
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
