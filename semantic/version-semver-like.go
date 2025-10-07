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

package semantic

import (
	"fmt"
	"math/big"
	"strings"
)

// semverLikeVersion is a version that is _like_ a version as defined by the
// Semantic Version specification, except with potentially unlimited numeric
// components and a leading "v"
type semverLikeVersion struct {
	LeadingV   bool
	Components components
	Build      string
	Original   string
}

func (v *semverLikeVersion) fetchComponentsAndBuild(maxComponents int) (components, string) {
	if maxComponents == -1 || len(v.Components) <= maxComponents {
		return v.Components, v.Build
	}

	comps := v.Components[:maxComponents]
	extra := v.Components[maxComponents:]

	build := v.Build

	for _, c := range extra {
		build += fmt.Sprintf(".%d", c)
	}

	return comps, build
}

func parseSemverLikeVersion(line string, maxComponents int) semverLikeVersion {
	v := parseSemverLike(line)

	comps, build := v.fetchComponentsAndBuild(maxComponents)

	return semverLikeVersion{
		LeadingV:   v.LeadingV,
		Components: comps,
		Build:      build,
		Original:   v.Original,
	}
}

func parseSemverLike(line string) semverLikeVersion {
	var comps []*big.Int
	originStr := line

	currentCom := ""
	foundBuild := false

	leadingV := strings.HasPrefix(line, "v")
	line = strings.TrimPrefix(line, "v")

	for _, c := range line {
		if foundBuild {
			currentCom += string(c)

			continue
		}

		// this is part of a component version
		if isASCIIDigit(c) {
			currentCom += string(c)

			continue
		}

		// at this point, we:
		//   1. might be parsing a component (as foundBuild != true)
		//   2. we're not looking at a part of a component (as c != number)
		//
		// so c must be either:
		//   1. a component terminator (.), or
		//   2. the start of the build string
		//
		// either way, we will be terminating the current component being
		// parsed (if any), so let's do that first
		if currentCom != "" {
			v, _ := new(big.Int).SetString(currentCom, 10)

			comps = append(comps, v)
			currentCom = ""
		}

		// a component terminator means there might be another component
		// afterwards, so don't start parsing the build string just yet
		if c == '.' {
			continue
		}

		// anything else is part of the build string
		foundBuild = true
		currentCom = string(c)
	}

	// if we looped over everything without finding a build string,
	// then what we were currently parsing is actually a component
	if !foundBuild && currentCom != "" {
		v, _ := new(big.Int).SetString(currentCom, 10)

		comps = append(comps, v)
		currentCom = ""
	}

	return semverLikeVersion{
		LeadingV:   leadingV,
		Components: comps,
		Build:      currentCom,
		Original:   originStr,
	}
}
