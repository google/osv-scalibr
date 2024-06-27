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

// Package list provides a public list of SCALIBR-internal detection plugins.
package list

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/detector/cis/generic_linux/etcpasswdpermissions"
	"github.com/google/osv-scalibr/detector/cve/cve202338408"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/detector/govulncheck/binary"
	"github.com/google/osv-scalibr/detector/weakcredentials/etcshadow"
	"github.com/google/osv-scalibr/log"

)

var (
	// names is a list of all available detectors and detector lists / groups.
	names = []string{
		// Higher level groupings.
		"all",
		"default",

		// Domain groupings.
		"cis",
		"cve",

		// Detector groupings.
		"govulncheck",
		"weakcreds",
	}
)

// CIS scanning related detectors.
var CIS []detector.Detector = []detector.Detector{&etcpasswdpermissions.Detector{}}

// CVE scanning related detectors.
var CVE []detector.Detector = []detector.Detector{&cve202338408.Detector{}}

// Govulncheck detectors.
var Govulncheck []detector.Detector = []detector.Detector{&binary.Detector{}}

// Weakcreds detectors for weak credentials.
var Weakcreds []detector.Detector = []detector.Detector{&etcshadow.Detector{}}

// Default detectors that are recommended to be enabled.
var Default []detector.Detector = []detector.Detector{}

// All detectors internal to SCALIBR.
var All []detector.Detector = slices.Concat(
	CIS,
	CVE,
	Govulncheck,
	Weakcreds,
)

var detectorNames = map[string][]detector.Detector{
	"cis":         CIS,
	"cve":         CVE,
	"govulncheck": Govulncheck,
	"weakcreds":   Weakcreds,
	"default":     Default,
	"all":         All,
}

func init() {
	for _, d := range All {
		register(d)
	}
}

// Names returns a list of all available detectors and detector lists / groups.
func Names() []string {
	// Defensive copy to avoid user mutation.
	var ns []string
	for _, n := range names {
		ns = append(ns, n)
	}
	return ns
}

func register(d detector.Detector) {
	if _, ok := detectorNames[strings.ToLower(d.Name())]; ok {
		log.Errorf("There are 2 detectors with the name: %q", d.Name())
		os.Exit(1)
	}
	detectorNames[strings.ToLower(d.Name())] = []detector.Detector{d}
}

// DetectorsFromNames returns a deduplicated list of detectors from a list of names.
func DetectorsFromNames(names []string) ([]detector.Detector, error) {
	resultMap := make(map[string]detector.Detector)
	for _, n := range names {
		if ds, ok := detectorNames[strings.ToLower(n)]; ok {
			for _, d := range ds {
				if _, ok := resultMap[d.Name()]; !ok {
					resultMap[d.Name()] = d
				}
			}
		} else {
			return nil, fmt.Errorf("unknown detector %s", n)
		}
	}
	result := make([]detector.Detector, 0, len(resultMap))
	for _, d := range resultMap {
		result = append(result, d)
	}
	return result, nil
}
