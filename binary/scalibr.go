// Copyright 2024 Google LLC
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

// The scalibr command wraps around the SCALIBR library to create a standalone
// CLI for extraction + detection with direct access to the local machine's filesystem.
package main

import (
	"flag"
	"os"

	"github.com/google/osv-scalibr/binary/cli"
	"github.com/google/osv-scalibr/binary/scanrunner"
	"github.com/google/osv-scalibr/log"
)

func main() {
	flags := parseFlags()
	os.Exit(scanrunner.RunScan(flags))
}

func parseFlags() *cli.Flags {
	root := flag.String("root", "", `The root dir used by detectors and by file walking during extraction (e.g.: "/", "c:\" or ".")`)
	resultFile := flag.String("result", "", "The path of the output scan result file")
	var output cli.Array
	flag.Var(&output, "o", "The path of the scanner outputs in various formats, e.g. -o textproto=result.textproto -o spdx23-json=result.spdx.json")
	extractorsToRun := flag.String("extractors", "default", "Comma-separated list of extractor plugins to run")
	detectorsToRun := flag.String("detectors", "default", "Comma-separated list of detectors plugins to run")
	dirsToSkip := flag.String("skip-dirs", "", "Comma-separated list of file paths to avoid traversing")
	skipDirRegex := flag.String("skip-dir-regex", "", "If the regex matches a directory, it will be skipped. The regex is matched against the absolute file path.")
	govulncheckDBPath := flag.String("govulncheck-db", "", "Path to the offline DB for the govulncheck detectors to use. Leave empty to run the detectors in online mode.")
	spdxDocumentName := flag.String("spdx-document-name", "", "The 'name' field for the output SPDX document")
	spdxDocumentNamespace := flag.String("spdx-document-namespace", "", "The 'documentNamespace' field for the output SPDX document")
	spdxCreators := flag.String("spdx-creators", "", "The 'creators' field for the output SPDX document. Format is --spdx-creators=creatortype1:creator1,creatortype2:creator2")
	verbose := flag.Bool("verbose", false, "Enable this to print debug logs")
	explicitExtractors := flag.Bool("explicit-extractors", false, "If set, the program will exit with an error if not all extractors required by enabled detectors are explicitly enabled.")

	flag.Parse()
	filesToExtract := flag.Args()

	flags := &cli.Flags{
		Root:                  *root,
		ResultFile:            *resultFile,
		Output:                output,
		ExtractorsToRun:       *extractorsToRun,
		DetectorsToRun:        *detectorsToRun,
		FilesToExtract:        filesToExtract,
		DirsToSkip:            *dirsToSkip,
		SkipDirRegex:          *skipDirRegex,
		GovulncheckDBPath:     *govulncheckDBPath,
		SPDXDocumentName:      *spdxDocumentName,
		SPDXDocumentNamespace: *spdxDocumentNamespace,
		SPDXCreators:          *spdxCreators,
		Verbose:               *verbose,
		ExplicitExtractors:    *explicitExtractors,
	}
	if err := cli.ValidateFlags(flags); err != nil {
		log.Errorf("Error parsing CLI args: %v", err)
		os.Exit(1)
	}
	return flags
}
