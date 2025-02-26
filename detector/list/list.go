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
	"github.com/google/osv-scalibr/detector/cve/cve202338408"
	"github.com/google/osv-scalibr/detector/govulncheck/binary"
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

// CVE scanning related detectors.
var CVE = InitMap{cve202338408.Name: {cve202338408.New}}

// Govulncheck detectors.
var Govulncheck = InitMap{binary.Name: {binary.New}}

// Weakcreds detectors for weak credentials.
var Weakcreds = InitMap{
	etcshadow.Name:   {etcshadow.New},
	filebrowser.Name: {filebrowser.New},
	winlocal.Name:    {winlocal.New},
}

// Default detectors that are recommended to be enabled.
var Default = InitMap{}

// All detectors internal to SCALIBR.
var All = concat(
	CIS,
	CVE,
	Govulncheck,
	Weakcreds,
)

var detectorNames = concat(All, InitMap{
	"cis":         vals(CIS),
	"cve":         vals(CVE),
	"govulncheck": vals(Govulncheck),
	"weakcreds":   vals(Weakcreds),
	"default":     vals(Default),
	"all":         vals(All),
})

func concat(InitMaps ...InitMap) InitMap {
	result := InitMap{}
	for _, m := range InitMaps {
		maps.Copy(result, m)
	}
	return result
}

func vals(InitMap InitMap) []InitFn {
	return slices.Concat(maps.Values(InitMap)...)
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
