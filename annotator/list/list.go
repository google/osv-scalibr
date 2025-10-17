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

// Package list provides a list of annotation plugins.
package list

import (
	"fmt"
	"maps"
	"slices"

	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/cachedir"
	"github.com/google/osv-scalibr/annotator/ffa/unknownbinariesanno"
	"github.com/google/osv-scalibr/annotator/misc/npmsource"
	noexecutabledpkg "github.com/google/osv-scalibr/annotator/noexecutable/dpkg"
	"github.com/google/osv-scalibr/annotator/osduplicate/apk"
	"github.com/google/osv-scalibr/annotator/osduplicate/cos"
	"github.com/google/osv-scalibr/annotator/osduplicate/dpkg"
	"github.com/google/osv-scalibr/annotator/osduplicate/rpm"
)

// InitFn is the annotator initializer function.
type InitFn func() annotator.Annotator

// InitMap is a map of annotator names to their initers.
type InitMap map[string][]InitFn

// VEX generation related annotators.
var VEX = InitMap{
	apk.Name:              {apk.New},
	cachedir.Name:         {cachedir.New},
	cos.Name:              {cos.New},
	dpkg.Name:             {dpkg.New},
	rpm.Name:              {rpm.NewDefault},
	noexecutabledpkg.Name: {noexecutabledpkg.New},
}

// Misc annotators.
var Misc = InitMap{npmsource.Name: {npmsource.New}}

// FFA (Full Filesystem Accountability) related annotators.
var FFA = InitMap{unknownbinariesanno.Name: {unknownbinariesanno.New}}

// Default detectors that are recommended to be enabled.
var Default = InitMap{cachedir.Name: {cachedir.New}}

// All annotators.
var All = concat(
	VEX,
	Misc,
	FFA,
)

var annotatorNames = concat(All, InitMap{
	"vex":                vals(VEX),
	"misc":               vals(Misc),
	"ffa":                vals(FFA),
	"annotators/default": vals(Default),
	"default":            vals(Default),
	"annotators/all":     vals(All),
	"all":                vals(All),
})

func concat(initMaps ...InitMap) InitMap {
	result := InitMap{}
	for _, m := range initMaps {
		maps.Copy(result, m)
	}
	return result
}

func vals(initMap InitMap) []InitFn {
	return slices.Concat(slices.Collect(maps.Values(initMap))...)
}

// AnnotatorsFromName returns a list of annotators from a name.
func AnnotatorsFromName(name string) ([]annotator.Annotator, error) {
	if initers, ok := annotatorNames[name]; ok {
		result := []annotator.Annotator{}
		for _, initer := range initers {
			result = append(result, initer())
		}
		return result, nil
	}
	return nil, fmt.Errorf("unknown annotator %q", name)
}
