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
func FindConstructors(pkgs []*packages.Package, types []*types.Named) []*Constructor {
	ctrs := []*Constructor{}
	for _, pkg := range pkgs {
		functions := findFunctions(pkg)
		// remove functions not starting with New
		functions = slices.DeleteFunc(functions, func(f *Function) bool {
			return !strings.HasPrefix(f.Fun.Name.Name, "New")
		})
		findAliases(functions)
		for _, impl := range types {
			for _, fn := range functions {
				if fn.Returns(impl) {
					ctrs = append(ctrs, &Constructor{Function: fn, Impl: impl})
				}
			}
		}
	}
	return ctrs
}

// findFunctions finds all the functions in the given pkg
func findFunctions(pkg *packages.Package) []*Function {
	seen := map[*ast.FuncDecl]*Function{}
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
			fns = append(fns, extractFunction(pkg, fn, seen))
			return true
		})
	}

	return fns
}

// extractFunction extracts concrete return types within the same package,
// if the function calls an external function it uses its return type as type (even if not concrete)
func extractFunction(pkg *packages.Package, fn *ast.FuncDecl, seen map[*ast.FuncDecl]*Function) *Function {
	if fn.Body == nil {
		return nil
	}
	if ts, ok := seen[fn]; ok {
		return ts
	}

	// handle nolint directive
	if hasNoLint(fn.Doc, Name) {
		res := &Function{Fun: fn, Pkg: pkg}
		seen[fn] = res
		return res
	}

	typesSet := map[types.Type]struct{}{}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			// Skip nested functions
			return false
		case *ast.ReturnStmt:
			for _, expr := range node.Results {
				switch call := expr.(type) {
				case *ast.CallExpr:
					if fnDecl := findFuncDecl(pkg, call.Fun); fnDecl != nil {
						// Recurse into the called function
						calledFn := extractFunction(pkg, fnDecl, seen)
						for _, t := range calledFn.ReturnTypes {
							typesSet[t] = struct{}{}
						}
					}
					// Also use the static return type of the call
					if typ := pkg.TypesInfo.TypeOf(call); typ != nil {
						typesSet[typ] = struct{}{}
					}
				default:
					// Normal return expression
					if typ := pkg.TypesInfo.TypeOf(expr); typ != nil {
						typesSet[typ] = struct{}{}
					}
				}
			}
		}
		return true
	})

	res := &Function{
		Fun: fn, Pkg: pkg,
		ReturnTypes: slices.Collect(maps.Keys(typesSet)),
	}
	seen[fn] = res
	return res
}

// findFuncDecl return searches the specified function in the given pkg
func findFuncDecl(pkg *packages.Package, fun ast.Expr) *ast.FuncDecl {
	// handle only identifier functions
	ident, ok := fun.(*ast.Ident)
	if !ok {
		return nil
	}

	// return it
	for _, file := range pkg.Syntax {
		for _, decl := range file.Decls {
			if d, ok := decl.(*ast.FuncDecl); ok && d.Name.Name == ident.Name {
				return d
			}
		}
	}
	return nil
}

// findAliases populates the .Aliases field in the given functions
//
// Two functions are considered aliases if one is prefix of another (New and NewWithClient or NewDefault)
//
// Note: suffixes such as "Default" and the name of the packages are removed from the name of the functions
func findAliases(functions []*Function) {
	// Build a map from normalized name to functions
	normMap := make(map[*Function]string)
	for _, f := range functions {
		fName := f.Fun.Name.Name
		fName = strings.TrimSuffix(fName, "Default")
		fName = strings.TrimSuffix(fName, capitalizeFirst(f.Pkg.Name))
		normMap[f] = fName
	}

	// Find aliases
	for _, f := range functions {
		fNormalized := normMap[f]
		for _, g := range functions {
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
