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
	"slices"

	"golang.org/x/tools/go/ast/inspector"
	"golang.org/x/tools/go/packages"
)

// FindImplementations returns all the implementations for the given interfaces
func FindImplementations(pkgs []*packages.Package, interfaces []*types.Named) map[*packages.Package][]*types.Named {
	implementations := make(map[*packages.Package][]*types.Named)

	filter := []ast.Node{(*ast.TypeSpec)(nil)}

	for _, pkg := range pkgs {
		inspector.New(pkg.Syntax).Preorder(filter, func(n ast.Node) {
			typeSpec := n.(*ast.TypeSpec)

			obj := pkg.TypesInfo.Defs[typeSpec.Name]
			if obj == nil {
				return
			}

			named, ok := obj.Type().(*types.Named)
			if !ok {
				return
			}
			// Skip interfaces themselves
			if _, ok := named.Underlying().(*types.Interface); ok {
				return
			}
			implementsAny := slices.ContainsFunc(interfaces, func(iface *types.Named) bool {
				return doesImplement(named, iface)
			})
			if implementsAny {
				implementations[pkg] = append(implementations[pkg], named)
			}
		})
	}

	return implementations
}

func doesImplement(named, iface *types.Named) bool {
	ifaceUnderlying, ok := iface.Underlying().(*types.Interface)
	if !ok {
		return false // iface is not actually an interface
	}

	// Handle generic interfaces
	if iface.TypeParams().Len() > 0 {
		// Collect type arguments by trying to infer from methods
		typeArgs := make([]types.Type, iface.TypeParams().Len())
		for i := range iface.TypeParams().Len() {
			// For simplicity, try to infer from the first method with enough parameters
			inferred := false
			for j := range named.NumMethods() {
				m := named.Method(j)
				sig, ok := m.Type().(*types.Signature)
				if !ok || sig.Params().Len() <= i {
					continue
				}
				typeArgs[i] = sig.Params().At(i).Type()
				inferred = true
				break
			}
			if !inferred {
				// Could not infer all type parameters, give up
				return false
			}
		}

		// Instantiate the interface with inferred type arguments
		instIface, err := types.Instantiate(nil, iface, typeArgs, false)
		if err != nil {
			return false
		}
		ifaceUnderlying = instIface.Underlying().(*types.Interface)
	}

	// Check both value and pointer receivers
	return types.Implements(named, ifaceUnderlying) || types.Implements(types.NewPointer(named), ifaceUnderlying)
}
