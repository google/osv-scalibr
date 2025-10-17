package plugger

import (
	"go/ast"
	"go/types"
	"maps"
	"slices"

	"golang.org/x/tools/go/packages"
)

// FindConstructors returns the constructor for the given implementations
func FindConstructors(pkgs []*packages.Package, implementations map[*packages.Package][]*types.Named) []*Constructor {
	ctrs := []*Constructor{}
	for _, pkg := range pkgs {
		functions := findFunctions(pkg)
		localImplemenations := implementations[pkg]
		for _, impl := range localImplemenations {
			for _, fn := range functions {
				if fn.Returns(impl) {
					ctrs = append(ctrs, NewConstructor(fn, impl))
				}
			}
		}
	}
	return ctrs
}

// findFunctions finds all the function in the given pkg
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
			returnTypes := extractReturnTypes(pkg, fn, nil)

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

// extractReturnTypes extracts concrete return types within the same package,
// if the function calls an external function it uses its return type as type (even if not concrete)
func extractReturnTypes(pkg *packages.Package, fn *ast.FuncDecl, seen map[*ast.FuncDecl]bool) []types.Type {
	if fn.Body == nil {
		return nil
	}
	if seen == nil {
		seen = make(map[*ast.FuncDecl]bool)
	}
	if seen[fn] {
		// Prevent infinite recursion on cyclic calls
		return nil
	}
	seen[fn] = true

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
						for _, t := range extractReturnTypes(pkg, fnDecl, seen) {
							typesSet[t] = struct{}{}
						}
						continue
					}
					// Fallback: use the static return type of the call
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

	return slices.Collect(maps.Keys(typesSet))
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
