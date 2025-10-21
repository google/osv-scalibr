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

// Package plugger contain the logic to find un-registered plugins
package plugger

import (
	"errors"
	"fmt"
	"go/types"
	"regexp"
	"slices"

	"golang.org/x/tools/go/packages"
)

// Config is the config used by the linter
var Config = &packages.Config{
	Mode:  packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
	Tests: false,
}

// Run returns a list of plugins that are not registered.
//
// Logic:
//
//  1. Find all interfaces matching iPattern.
//
//  2. Find all types that implement those interfaces.
//
//  3. Identify all files in which the constructors for these types are declared
//
//  4. For each file, there must be at least one constructor call (!!!outside of the package!!!):
//
//     if none exist, the plugin is considered not registered.
func Run(iPattern, excludePkgPattern *regexp.Regexp, pkgsPattern []string) ([]*Constructor, error) {
	pkgs, err := packages.Load(Config, pkgsPattern...)
	if err != nil {
		return nil, fmt.Errorf("failed to load packages: %w", err)
	}

	pkgs = slices.DeleteFunc(pkgs, func(pkg *packages.Package) bool {
		return excludePkgPattern.MatchString(pkg.String())
	})

	interfaces := FindInterfaces(pkgs, iPattern)
	if len(interfaces) == 0 {
		return nil, errors.New("no interface found")
	}

	implementations := FindImplementations(pkgs, interfaces)
	ctrs := FindConstructors(pkgs, implementations)
	usages := FindUsages(pkgs, ctrs)
	return notRegistered(ctrs, usages), nil
}

func notRegistered(all, used []*Constructor) []*Constructor {
	usedSet := make(map[*types.Named]struct{}, len(used))
	for _, c := range used {
		usedSet[c.Impl] = struct{}{}
	}

	var diff []*Constructor
	for _, c := range all {
		if _, exists := usedSet[c.Impl]; !exists {
			diff = append(diff, c)
		}
	}

	return diff
}
