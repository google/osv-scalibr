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
	"go/token"
	"go/types"
	"slices"
	"strings"

	"golang.org/x/tools/go/ast/inspector"
	"golang.org/x/tools/go/packages"
)

// FindImplementations returns all the implementations for the given interfaces
func FindImplementations(pkgs []*packages.Package, interfaces []*types.Named) []*types.Named {
	implementations := []*types.Named{}

	filter := []ast.Node{(*ast.GenDecl)(nil)}

	for _, pkg := range pkgs {
		inspector.New(pkg.Syntax).Preorder(filter, func(n ast.Node) {
			genDecl := n.(*ast.GenDecl)
			if genDecl.Tok != token.TYPE {
				return
			}

			if hasNoLint(genDecl.Doc, Name) {
				return
			}

			for _, spec := range genDecl.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}

				obj := pkg.TypesInfo.Defs[typeSpec.Name]
				if obj == nil {
					continue
				}

				named, ok := obj.Type().(*types.Named)
				if !ok {
					continue
				}

				// Skip interfaces themselves
				if _, ok := named.Underlying().(*types.Interface); ok {
					continue
				}
				implementsAny := slices.ContainsFunc(interfaces, func(iface *types.Named) bool {
					return doesImplement(named, iface)
				})
				if implementsAny {
					implementations = append(implementations, named)
				}
			}
		})
	}

	return implementations
}

func hasNoLint(commentGroup *ast.CommentGroup, name string) bool {
	if commentGroup == nil {
		return false
	}
	for _, comment := range commentGroup.List {
		text := comment.Text
		linters, ok := strings.CutPrefix(text, "//nolint:")
		if !ok {
			continue
		}

		// remove comment after //nolint, ex:
		//
		//	//nolint:plugger //something
		linters, _, _ = strings.Cut(linters, " ")

		// return true if one of the comma separated linter is plugger
		if slices.Contains(strings.Split(linters, ","), name) {
			return true
		}
	}
	return false
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
