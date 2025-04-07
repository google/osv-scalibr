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
	os.Exit(run(os.Args))
}

func run(args []string) int {
	var subcommand string
	if len(args) >= 2 {
		subcommand = args[1]
	}
	switch subcommand {
	case "scan":
		flags, err := parseFlags(args[2:])
		if err != nil {
			log.Errorf("Error parsing CLI args: %v", err)
			return 1
		}
		return scanrunner.RunScan(flags)
	default:
		// Assume 'scan' if subcommand is not recognized/specified.
		flags, err := parseFlags(args[1:])
		if err != nil {
			log.Errorf("Error parsing CLI args: %v", err)
			return 1
		}
		return scanrunner.RunScan(flags)
	}
}

func parseFlags(args []string) (*cli.Flags, error) {
	fs := flag.NewFlagSet("scalibr", flag.ExitOnError)
	root := fs.String("root", "", `The root dir used by detectors and by file walking during extraction (e.g.: "/", "c:\" or ".")`)
	resultFile := fs.String("result", "", "The path of the output scan result file")
	var output cli.Array
	fs.Var(&output, "o", "The path of the scanner outputs in various formats, e.g. -o textproto=result.textproto -o spdx23-json=result.spdx.json -o cdx-json=result.cyclonedx.json")
	extractorsToRun := cli.NewStringListFlag([]string{"default"})
	fs.Var(&extractorsToRun, "extractors", "Comma-separated list of extractor plugins to run")
	detectorsToRun := cli.NewStringListFlag([]string{"default"})
	fs.Var(&detectorsToRun, "detectors", "Comma-separated list of detectors plugins to run")
	ignoreSubDirs := fs.Bool("ignore-sub-dirs", false, "Non-recursive mode: Extract only the files only the files in the top-level directory and skip sub-directories")
	var dirsToSkip cli.StringListFlag
	fs.Var(&dirsToSkip, "skip-dirs", "Comma-separated list of file paths to avoid traversing")
	skipDirRegex := fs.String("skip-dir-regex", "", "If the regex matches a directory, it will be skipped. The regex is matched against the absolute file path.")
	skipDirGlob := fs.String("skip-dir-glob", "", "If the glob matches a directory, it will be skipped. The glob is matched against the absolute file path.")
	useGitignore := fs.Bool("use-gitignore", false, "Skip files declared in .gitignore files in source repos.")
	remoteImage := fs.String("remote-image", "", "The remote image to scan. If specified, SCALIBR pulls and scans this image instead of the local filesystem.")
	imagePlatform := fs.String("image-platform", "", "The platform of the remote image to scan. If not specified, the platform of the client is used. Format is os/arch (e.g. linux/arm64)")
	govulncheckDBPath := fs.String("govulncheck-db", "", "Path to the offline DB for the govulncheck detectors to use. Leave empty to run the detectors in online mode.")
	spdxDocumentName := fs.String("spdx-document-name", "", "The 'name' field for the output SPDX document")
	spdxDocumentNamespace := fs.String("spdx-document-namespace", "", "The 'documentNamespace' field for the output SPDX document")
	spdxCreators := fs.String("spdx-creators", "", "The 'creators' field for the output SPDX document. Format is --spdx-creators=creatortype1:creator1,creatortype2:creator2")
	cdxComponentName := fs.String("cdx-component-name", "", "The 'metadata.component.name' field for the output CDX document")
	cdxComponentVersion := fs.String("cdx-component-version", "", "The 'metadata.component.version' field for the output CDX document")
	cdxAuthors := fs.String("cdx-authors", "", "The 'authors' field for the output CDX document. Format is --cdx-authors=author1,author2")
	verbose := fs.Bool("verbose", false, "Enable this to print debug logs")
	explicitExtractors := fs.Bool("explicit-extractors", false, "If set, the program will exit with an error if not all extractors required by enabled detectors are explicitly enabled.")
	filterByCapabilities := fs.Bool("filter-by-capabilities", true, "If set, plugins whose requirements (network access, OS, etc.) aren't satisfied by the scanning environment will be silently disabled instead of throwing a validation error.")
	windowsAllDrives := fs.Bool("windows-all-drives", false, "Scan all drives on Windows")
	offline := fs.Bool("offline", false, "Offline mode: Run only plugins that don't require network access")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	pathsToExtract := fs.Args()

	flags := &cli.Flags{
		Root:                  *root,
		ResultFile:            *resultFile,
		Output:                output,
		ExtractorsToRun:       extractorsToRun.GetSlice(),
		DetectorsToRun:        detectorsToRun.GetSlice(),
		PathsToExtract:        pathsToExtract,
		IgnoreSubDirs:         *ignoreSubDirs,
		DirsToSkip:            dirsToSkip.GetSlice(),
		SkipDirRegex:          *skipDirRegex,
		SkipDirGlob:           *skipDirGlob,
		UseGitignore:          *useGitignore,
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
		Offline:               *offline,
	}
	if err := cli.ValidateFlags(flags); err != nil {
		return nil, err
	}
	return flags, nil
}
