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

				implementsAny := slices.ContainsFunc(interfaces, func(iface *types.Named) bool {
					// Pass the T type and the package object (which is needed for the types.Selection.Obj().Pkg() check in Lookup)
					return doesImplement(named, iface) || doesImplement(types.NewPointer(named), iface)
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

// doesImplement checks if the named type implements the named interface,
// using heuristic instantiation logic for generic interfaces.
func doesImplement(t types.Type, iface *types.Named) bool {
	ifaceType, ok := iface.Underlying().(*types.Interface)
	if !ok {
		return false
	}

	// Either a non-generic interface or a generic interface with no methods
	// we can't deduce type arguments.
	if iface.TypeParams().Len() == 0 || ifaceType.NumMethods() == 0 {
		return types.Satisfies(t, ifaceType)
	}

	// Generic interface

	concreteMethods := types.NewMethodSet(t)
	iTypeArgs := make([]types.Type, iface.TypeParams().Len())
	iTypeParams := iface.TypeParams()

	// check every method in the generic interface template
	for iMethod := range ifaceType.Methods() {
		// Search the method by name
		mSelected := concreteMethods.Lookup(iMethod.Pkg(), iMethod.Name())
		// Method is missing, it's impossible this type implements the interface
		if mSelected == nil {
			return false
		}

		iSignature := iMethod.Type().(*types.Signature)
		cSignature := mSelected.Type().(*types.Signature)

		// Check if the types match (both params and results)
		paramsMatch(iTypeParams, iSignature.Params(), cSignature.Params(), iTypeArgs)
		paramsMatch(iTypeParams, iSignature.Results(), cSignature.Results(), iTypeArgs)
	}

	// Check if all the required type arguments were found.
	if slices.Contains(iTypeArgs, nil) {
		return false
	}

	// Instantiate the generic interface (e.g., Validator[int])
	instantiated, err := types.Instantiate(nil, iface, iTypeArgs, false)
	if err != nil {
		return false
	}

	// Final check: t satisfies the instantiated interface
	return types.Satisfies(t, instantiated.Underlying().(*types.Interface))
}

// paramsMatch compares the template parameter list (iParams) against the concrete parameter
// list (cParams) to fill the typeArgs slice with concrete types.
func paramsMatch(iTypeParams *types.TypeParamList, iParams, cParams *types.Tuple, typeArgs []types.Type) {
	if iParams.Len() != cParams.Len() {
		return
	}

	for j := range iParams.Len() {
		iType := iParams.At(j).Type()

		tp, isTypeParam := iType.(*types.TypeParam)
		if !isTypeParam {
			continue
		}
		// If the interface type at this position is a type parameter (e.g., S in Validator[S])
		// Find its index in the interface's overall type parameter list
		for i := range iTypeParams.Len() {
			p := iTypeParams.At(i)
			if p == tp {
				typeArgs[i] = cParams.At(j).Type()
				break
			}
		}
	}
}
