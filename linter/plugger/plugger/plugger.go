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
	"fmt"
	"go/ast"
	"go/types"
	"slices"

	"golang.org/x/tools/go/packages"
)

// Name is the name of the linter
var Name = "plugger"

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
//  3. Identify all packages in which the constructors for these types are declared
//
//  4. Each constructor must be called at least once outside of the pkg. Note:
//
//     - 2 functions returning the same type declared in the current pkg are considered aliases (only 1 of those must be called)
//
//     - 2 functions returning the same type declared in another pkg, are considered separate (both must be called)
//
//     if none exist, the plugin is considered not registered.
func Run(interfaceNames []string, pkgsPattern []string) ([]*Constructor, error) {
	pkgs, err := packages.Load(Config, pkgsPattern...)
	if err != nil {
		return nil, fmt.Errorf("failed to load packages: %w", err)
	}

	pkgs = FilterNoLintPackages(pkgs)

	interfaces := FindInterfaces(pkgs, interfaceNames)
	if len(interfaceNames) != len(interfaces) {
		return nil, fmt.Errorf("%d interfaces are specified but only %d are found: %v",
			len(interfaceNames), len(interfaces), interfaces,
		)
	}

	implementations := FindImplementations(pkgs, interfaces)
	ctrs := FindConstructors(pkgs, slices.Concat(implementations, interfaces))
	usages := FindUsages(pkgs, ctrs)
	return notRegistered(ctrs, usages), nil
}

// FilterNoLintPackages filters out pkgs which have a nolint directive
func FilterNoLintPackages(pkgs []*packages.Package) []*packages.Package {
	return slices.DeleteFunc(pkgs, func(pkg *packages.Package) bool {
		for _, f := range pkg.Syntax {
			for _, cg := range f.Comments {
				if hasNoLint(cg, Name) {
					return true
				}
			}
		}
		return false
	})
}

// notRegistered return a list of non-registered plugins
func notRegistered(all, used []*Constructor) []*Constructor {
	type key struct {
		Impl *types.Named
		Pkg  *packages.Package
		Fun  *ast.FuncDecl
	}

	usedSet := make(map[key]struct{}, len(used))
	for _, c := range used {
		usedSet[key{Fun: c.Fun}] = struct{}{}
		// mark the type as "covered" only for types declared in the same pkg
		if c.Impl.Obj().Pkg() == c.Pkg.Types {
			usedSet[key{Impl: c.Impl, Pkg: c.Pkg}] = struct{}{}
		}
		for _, called := range c.Called {
			usedSet[key{Fun: called.Fun}] = struct{}{}
		}
	}

	var diff []*Constructor
	for _, c := range all {
		_, returnedTypeCovered := usedSet[key{Impl: c.Impl, Pkg: c.Pkg}]
		_, calledDirectly := usedSet[key{Fun: c.Fun}]
		if !returnedTypeCovered && !calledDirectly {
			diff = append(diff, c)
		}
	}

	return diff
}
