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

// Package list provides a public list of SCALIBR-internal detection plugins.
package list

import (
	"fmt"
	"slices"

	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/detector/cis/generic_linux/etcpasswdpermissions"
	"github.com/google/osv-scalibr/detector/cve/untested/cve202011978"
	"github.com/google/osv-scalibr/detector/cve/untested/cve202016846"
	"github.com/google/osv-scalibr/detector/cve/untested/cve202233891"
	"github.com/google/osv-scalibr/detector/cve/untested/cve202338408"
	"github.com/google/osv-scalibr/detector/cve/untested/cve20236019"
	"github.com/google/osv-scalibr/detector/cve/untested/cve20242912"
	"github.com/google/osv-scalibr/detector/govulncheck/binary"
	"github.com/google/osv-scalibr/detector/weakcredentials/codeserver"
	"github.com/google/osv-scalibr/detector/weakcredentials/etcshadow"
	"github.com/google/osv-scalibr/detector/weakcredentials/filebrowser"
	"github.com/google/osv-scalibr/detector/weakcredentials/winlocal"
	"github.com/google/osv-scalibr/plugin"
	"golang.org/x/exp/maps"
)

// InitFn is the detector initializer function.
type InitFn func() detector.Detector

// InitMap is a map of detector names to their initers.
type InitMap map[string][]InitFn

// CIS scanning related detectors.
var CIS = InitMap{etcpasswdpermissions.Name: {etcpasswdpermissions.New}}

// Govulncheck detectors.
var Govulncheck = InitMap{binary.Name: {binary.New}}

// Untested CVE scanning related detectors - since they don't have proper testing they
// might not work as expected in the future.
// TODO(b/405223999): Add tests.
var Untested = InitMap{
	// CVE-2023-38408 OpenSSH detector.
	cve202338408.Name: {cve202338408.New},
	// CVE-2022-33891 Spark UI detector.
	cve202233891.Name: {cve202233891.New},
	// CVE-2020-16846 Salt detector.
	cve202016846.Name: {cve202016846.New},
	// CVE-2023-6019 Ray Dashboard detector.
	cve20236019.Name: {cve20236019.New},
	// CVE-2020-11978 Apache Airflow detector.
	cve202011978.Name: {cve202011978.New},
	// CVE-2024-2912 BentoML detector.
	cve20242912.Name: {cve20242912.New},
}

// Weakcreds detectors for weak credentials.
var Weakcreds = InitMap{
	codeserver.Name:  {codeserver.NewDefault},
	etcshadow.Name:   {etcshadow.New},
	filebrowser.Name: {filebrowser.New},
	winlocal.Name:    {winlocal.New},
}

// Default detectors that are recommended to be enabled.
var Default = InitMap{}

// All detectors internal to SCALIBR.
var All = concat(
	CIS,
	Govulncheck,
	Weakcreds,
	Untested,
)

var detectorNames = concat(All, InitMap{
	"cis":         vals(CIS),
	"govulncheck": vals(Govulncheck),
	"weakcreds":   vals(Weakcreds),
	"untested":    vals(Untested),
	"default":     vals(Default),
	"all":         vals(All),
})

func concat(initMaps ...InitMap) InitMap {
	result := InitMap{}
	for _, m := range initMaps {
		maps.Copy(result, m)
	}
	return result
}

func vals(initMap InitMap) []InitFn {
	return slices.Concat(maps.Values(initMap)...)
}

// FromCapabilities returns all detectors that can run under the specified
// capabilities (OS, direct filesystem access, network access, etc.) of the
// scanning environment.
func FromCapabilities(capabs *plugin.Capabilities) []detector.Detector {
	all := []detector.Detector{}
	for _, initers := range All {
		for _, initer := range initers {
			all = append(all, initer())
		}
	}
	return FilterByCapabilities(all, capabs)
}

// FilterByCapabilities returns all detectors from the given list that can run
// under the specified capabilities (OS, direct filesystem access, network
// access, etc.) of the scanning environment.
func FilterByCapabilities(dets []detector.Detector, capabs *plugin.Capabilities) []detector.Detector {
	result := []detector.Detector{}
	for _, det := range dets {
		if err := plugin.ValidateRequirements(det, capabs); err == nil {
			result = append(result, det)
		}
	}
	return result
}

// DetectorsFromNames returns a deduplicated list of detectors from a list of names.
func DetectorsFromNames(names []string) ([]detector.Detector, error) {
	resultMap := make(map[string]detector.Detector)
	for _, n := range names {
		if initers, ok := detectorNames[n]; ok {
			for _, initer := range initers {
				d := initer()
				if _, ok := resultMap[d.Name()]; !ok {
					resultMap[d.Name()] = d
				}
			}
		} else {
			return nil, fmt.Errorf("unknown detector %q", n)
		}
	}
	result := make([]detector.Detector, 0, len(resultMap))
	for _, d := range resultMap {
		result = append(result, d)
	}
	return result, nil
}
