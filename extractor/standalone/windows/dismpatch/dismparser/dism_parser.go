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

// Package dismparser has methods that can be used to parse DISM output
package dismparser

import (
	"errors"
	"regexp"
	"strings"
)

var (
	// ErrParsingError indicates an error while parsing the DISM output.
	ErrParsingError = errors.New("Could not parse DISM output successfully")

	versionRegexp = regexp.MustCompile(`~(\d+\.\d+\.\d+\.\d+)$`)
)

// DismPkg reports information about a package as reported by the DISM tool.
type DismPkg struct {
	PackageIdentity string
	PackageVersion  string
	State           string
	ReleaseType     string
	InstallTime     string
}

// Parse parses dism output into an array of dismPkgs.
func Parse(input string) ([]DismPkg, string, error) {
	pkgs := strings.Split(input, "Package Id")

	pkgExp, err := regexp.Compile("entity :(.*)\n*State :(.*)\n*Release Type :(.*)\n*Install Time :(.*)\n*")
	if err != nil {
		return nil, "", err
	}

	imgExp, err := regexp.Compile("Image Version: (.*)")
	if err != nil {
		return nil, "", err
	}

	imgVersion := ""
	dismPkgs := []DismPkg{}

	for _, pkg := range pkgs {
		matches := pkgExp.FindStringSubmatch(pkg)
		if len(matches) > 4 {
			dismPkg := DismPkg{
				PackageIdentity: strings.TrimSpace(matches[1]),
				State:           strings.TrimSpace(matches[2]),
				ReleaseType:     strings.TrimSpace(matches[3]),
				InstallTime:     strings.TrimSpace(matches[4]),
			}
			dismPkg.PackageVersion = findVersion(dismPkg.PackageIdentity)
			dismPkgs = append(dismPkgs, dismPkg)
		} else {
			// this is the first entry that has the image version
			matches = imgExp.FindStringSubmatch(pkg)
			if len(matches) > 1 {
				imgVersion = strings.TrimSpace(matches[1])
			}
		}
	}

	if len(dismPkgs) == 0 {
		return nil, "", ErrParsingError
	}

	return dismPkgs, imgVersion, nil
}

func findVersion(identity string) string {
	pkgVer := versionRegexp.FindStringSubmatch(identity)
	if len(pkgVer) > 1 {
		return pkgVer[1]
	}
	return ""
}
