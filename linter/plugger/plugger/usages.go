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
