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

	"golang.org/x/tools/go/ast/inspector"
	"golang.org/x/tools/go/packages"
)

// FindUsages returns all constructors that are used in the given packages.
func FindUsages(pkgs []*packages.Package, ctrs []*Constructor) []*Constructor {
	used := map[*Constructor]struct{}{}

	// Map functions to constructors
	funcMap := map[*types.Func]*Constructor{}
	for _, c := range ctrs {
		if c.Fun == nil || c.Pkg == nil {
			continue
		}
		if obj, ok := c.Pkg.TypesInfo.Defs[c.Fun.Name].(*types.Func); ok {
			funcMap[obj] = c
		}
	}

	filter := []ast.Node{(*ast.Ident)(nil), (*ast.SelectorExpr)(nil)}

	for _, pkg := range pkgs {
		inspector.New(pkg.Syntax).Preorder(filter, func(n ast.Node) {
			var fn *types.Func

			switch node := n.(type) {
			case *ast.Ident:
				if obj, ok := pkg.TypesInfo.Uses[node].(*types.Func); ok {
					fn = obj
				}
			case *ast.SelectorExpr:
				if obj, ok := pkg.TypesInfo.Uses[node.Sel].(*types.Func); ok {
					fn = obj
				}
			}

			if fn == nil || fn.Pkg() == nil || fn.Pkg().Name() == pkg.Name {
				return
			}

			if c, ok := funcMap[fn]; ok {
				used[c] = struct{}{}
			}
		})
	}

	return slices.Collect(maps.Keys(used))
}
