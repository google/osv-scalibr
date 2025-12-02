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

package plugger

import (
	"go/ast"
	"go/types"
	"maps"
	"slices"
	"strings"
	"unicode"

	"golang.org/x/tools/go/packages"
)

// FindConstructors returns the constructor for the given types
func FindConstructors(pkgs []*packages.Package, nTypes []*types.Named) []*Constructor {
	ctrs := map[*Function]*Constructor{}
	for _, pkg := range pkgs {
		functions := findFunctions(pkg)
		// remove functions not starting with New
		functions = slices.DeleteFunc(functions, func(f *Function) bool {
			return !strings.HasPrefix(f.Fun.Name.Name, "New")
		})
		findAliases(functions)
		for _, impl := range nTypes {
			for _, fn := range functions {
				if fn.Returns(impl) {
					if ctr, ok := ctrs[fn]; ok {
						ctr.Registers = append(ctr.Registers, impl)
						ctrs[fn] = ctr
					} else {
						ctrs[fn] = &Constructor{Function: fn, Registers: []*types.Named{impl}}
					}
				}
			}
		}
	}
	res := slices.Collect(maps.Values(ctrs))
	return res
}

// findFunctions finds all the functions in the given pkg
func findFunctions(pkg *packages.Package) []*Function {
	fns := []*Function{}
	for _, file := range pkg.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Type.Results == nil || !fn.Name.IsExported() {
				return true
			}

			if fn.Recv != nil {
				return true
			}

			// skip excluded functions
			if hasNoLint(fn.Doc, Name) {
				return true
			}

			var returnTypes []types.Type
			for _, field := range fn.Type.Results.List {
				returnTypes = append(returnTypes, pkg.TypesInfo.TypeOf(field.Type))
			}

			fns = append(fns, &Function{
				Fun:         fn,
				Pkg:         pkg,
				ReturnTypes: returnTypes,
			})
			return true
		})
	}

	return fns
}

// findAliases populates the .Aliases field in the given functions
//
// Two functions are considered aliases if one is prefix of another (New and NewWithClient or NewDefault)
//
// Note: suffixes such as "Default" and the name of the packages are removed from the name of the functions
func findAliases(ctrs []*Function) {
	// Build a map from normalized name to functions
	normMap := make(map[*Function]string)
	for _, f := range ctrs {
		fName := f.Fun.Name.Name
		fName = strings.TrimSuffix(fName, "Default")
		fName = strings.TrimSuffix(fName, capitalizeFirst(f.Pkg.Name))
		normMap[f] = fName
	}

	// Find aliases
	for _, f := range ctrs {
		fNormalized := normMap[f]
		for _, g := range ctrs {
			if f == g {
				continue
			}
			gNormalized := normMap[g]
			if strings.HasPrefix(gNormalized, fNormalized) || strings.HasPrefix(fNormalized, gNormalized) {
				f.Aliases = append(f.Aliases, g)
			}
		}
	}
}

func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	// Convert first rune to uppercase, rest stays the same
	runes := []rune(s)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}
