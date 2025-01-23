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
	flag.Var(&output, "o", "The path of the scanner outputs in various formats, e.g. -o textproto=result.textproto -o spdx23-json=result.spdx.json -o cdx-json=result.cyclonedx.json")
	extractorsToRun := cli.NewStringListFlag([]string{"default"})
	flag.Var(&extractorsToRun, "extractors", "Comma-separated list of extractor plugins to run")
	detectorsToRun := cli.NewStringListFlag([]string{"default"})
	flag.Var(&detectorsToRun, "detectors", "Comma-separated list of detectors plugins to run")
	var dirsToSkip cli.StringListFlag
	flag.Var(&dirsToSkip, "skip-dirs", "Comma-separated list of file paths to avoid traversing")
	skipDirRegex := flag.String("skip-dir-regex", "", "If the regex matches a directory, it will be skipped. The regex is matched against the absolute file path.")
	skipDirGlob := flag.String("skip-dir-glob", "", "If the glob matches a directory, it will be skipped. The glob is matched against the absolute file path.")
	remoteImage := flag.String("remote-image", "", "The remote image to scan. If specified, SCALIBR pulls and scans this image instead of the local filesystem.")
	imagePlatform := flag.String("image-platform", "", "The platform of the remote image to scan. If not specified, the platform of the client is used. Format is os/arch (e.g. linux/arm64)")
	govulncheckDBPath := flag.String("govulncheck-db", "", "Path to the offline DB for the govulncheck detectors to use. Leave empty to run the detectors in online mode.")
	spdxDocumentName := flag.String("spdx-document-name", "", "The 'name' field for the output SPDX document")
	spdxDocumentNamespace := flag.String("spdx-document-namespace", "", "The 'documentNamespace' field for the output SPDX document")
	spdxCreators := flag.String("spdx-creators", "", "The 'creators' field for the output SPDX document. Format is --spdx-creators=creatortype1:creator1,creatortype2:creator2")
	cdxComponentName := flag.String("cdx-component-name", "", "The 'metadata.component.name' field for the output CDX document")
	cdxComponentVersion := flag.String("cdx-component-version", "", "The 'metadata.component.version' field for the output CDX document")
	cdxAuthors := flag.String("cdx-authors", "", "The 'authors' field for the output CDX document. Format is --cdx-authors=author1,author2")
	verbose := flag.Bool("verbose", false, "Enable this to print debug logs")
	explicitExtractors := flag.Bool("explicit-extractors", false, "If set, the program will exit with an error if not all extractors required by enabled detectors are explicitly enabled.")
	filterByCapabilities := flag.Bool("filter-by-capabilities", true, "If set, plugins whose requirements (network access, OS, etc.) aren't satisfied by the scanning environment will be silently disabled instead of throwing a validation error.")
	windowsAllDrives := flag.Bool("windows-all-drives", false, "Scan all drives on Windows")

	flag.Parse()
	filesToExtract := flag.Args()

	flags := &cli.Flags{
		Root:                  *root,
		ResultFile:            *resultFile,
		Output:                output,
		ExtractorsToRun:       extractorsToRun.GetSlice(),
		DetectorsToRun:        detectorsToRun.GetSlice(),
		FilesToExtract:        filesToExtract,
		DirsToSkip:            dirsToSkip.GetSlice(),
		SkipDirRegex:          *skipDirRegex,
		SkipDirGlob:           *skipDirGlob,
		RemoteImage:           *remoteImage,
		ImagePlatform:         *imagePlatform,
		GovulncheckDBPath:     *govulncheckDBPath,
		SPDXDocumentName:      *spdxDocumentName,
		SPDXDocumentNamespace: *spdxDocumentNamespace,
		SPDXCreators:          *spdxCreators,
		CDXComponentName:      *cdxComponentName,
		CDXComponentVersion:   *cdxComponentVersion,
		CDXAuthors:            *cdxAuthors,
		Verbose:               *verbose,
		ExplicitExtractors:    *explicitExtractors,
		FilterByCapabilities:  *filterByCapabilities,
		WindowsAllDrives:      *windowsAllDrives,
	}
	if err := cli.ValidateFlags(flags); err != nil {
		log.Errorf("Error parsing CLI args: %v", err)
		os.Exit(1)
	}
	return flags
}
